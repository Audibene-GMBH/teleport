// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package appaccess

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/stretchr/testify/require"
)

type AppTestOptions struct {
	ExtraRootApps        []service.App
	ExtraLeafApps        []service.App
	RootClusterListeners helpers.InstanceListenerSetupFunc
	LeafClusterListeners helpers.InstanceListenerSetupFunc

	RootConfig func(config *service.Config)
	LeafConfig func(config *service.Config)
}

// Setup configures all clusters and servers needed for a test.
func Setup(t *testing.T) *Pack {
	return SetupWithOptions(t, AppTestOptions{})
}

// SetupWithOptions configures app access test with custom options.
func SetupWithOptions(t *testing.T, opts AppTestOptions) *Pack {
	tr := utils.NewTracer(utils.ThisFunction()).Start()
	defer tr.Stop()

	log := utils.NewLoggerForTests()

	// Insecure development mode needs to be set because the web proxy uses a
	// self-signed certificate during tests.
	lib.SetInsecureDevMode(true)

	p := &Pack{
		rootAppName:        "app-01",
		rootAppPublicAddr:  "app-01.example.com",
		rootAppClusterName: "example.com",
		rootMessage:        uuid.New().String(),

		rootWSAppName:    "ws-01",
		rootWSPublicAddr: "ws-01.example.com",
		rootWSMessage:    uuid.New().String(),

		rootWSSAppName:    "wss-01",
		rootWSSPublicAddr: "wss-01.example.com",
		rootWSSMessage:    uuid.New().String(),

		rootTCPAppName:    "tcp-01",
		rootTCPPublicAddr: "tcp-01.example.com",
		rootTCPMessage:    uuid.New().String(),

		leafAppName:        "app-02",
		leafAppPublicAddr:  "app-02.example.com",
		leafAppClusterName: "leaf.example.com",
		leafMessage:        uuid.New().String(),

		leafWSAppName:    "ws-02",
		leafWSPublicAddr: "ws-02.example.com",
		leafWSMessage:    uuid.New().String(),

		leafWSSAppName:    "wss-02",
		leafWSSPublicAddr: "wss-02.example.com",
		leafWSSMessage:    uuid.New().String(),

		leafTCPAppName:    "tcp-02",
		leafTCPPublicAddr: "tcp-02.example.com",
		leafTCPMessage:    uuid.New().String(),

		jwtAppName:        "app-03",
		jwtAppPublicAddr:  "app-03.example.com",
		jwtAppClusterName: "example.com",

		headerAppName:        "app-04",
		headerAppPublicAddr:  "app-04.example.com",
		headerAppClusterName: "example.com",

		wsHeaderAppName:        "ws-header",
		wsHeaderAppPublicAddr:  "ws-header.example.com",
		wsHeaderAppClusterName: "example.com",

		flushAppName:        "app-05",
		flushAppPublicAddr:  "app-05.example.com",
		flushAppClusterName: "example.com",
	}

	createHandler := func(handler func(conn *websocket.Conn)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			upgrader := websocket.Upgrader{
				ReadBufferSize:  1024,
				WriteBufferSize: 1024,
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			require.NoError(t, err)
			handler(conn)
		}
	}

	// Start a few different HTTP server that will be acting like a proxied application.
	rootServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, p.rootMessage)
	}))
	t.Cleanup(rootServer.Close)
	// Websockets server in root cluster (ws://).
	rootWSServer := httptest.NewServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.rootWSMessage))
		conn.Close()
	}))
	t.Cleanup(rootWSServer.Close)
	// Secure websockets server in root cluster (wss://).
	rootWSSServer := httptest.NewTLSServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.rootWSSMessage))
		conn.Close()
	}))
	t.Cleanup(rootWSSServer.Close)
	// Plain TCP application in root cluster (tcp://).
	rootTCPServer := newTCPServer(t, func(c net.Conn) {
		c.Write([]byte(p.rootTCPMessage))
		c.Close()
	})
	t.Cleanup(func() { rootTCPServer.Close() })
	// HTTP server in leaf cluster.
	leafServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, p.leafMessage)
	}))
	t.Cleanup(leafServer.Close)
	// Websockets server in leaf cluster (ws://).
	leafWSServer := httptest.NewServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.leafWSMessage))
		conn.Close()
	}))
	t.Cleanup(leafWSServer.Close)
	// Secure websockets server in leaf cluster (wss://).
	leafWSSServer := httptest.NewTLSServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.leafWSSMessage))
		conn.Close()
	}))
	t.Cleanup(leafWSSServer.Close)
	// Plain TCP application in leaf cluster (tcp://).
	leafTCPServer := newTCPServer(t, func(c net.Conn) {
		c.Write([]byte(p.leafTCPMessage))
		c.Close()
	})
	t.Cleanup(func() { leafTCPServer.Close() })
	// JWT server writes generated JWT token in the response.
	jwtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, r.Header.Get(teleport.AppJWTHeader))
	}))
	t.Cleanup(jwtServer.Close)
	// Websocket header server dumps initial HTTP upgrade request in the response.
	wsHeaderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		require.NoError(t, err)
		reqDump, err := httputil.DumpRequest(r, false)
		require.NoError(t, err)
		require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, reqDump))
		require.NoError(t, conn.Close())
	}))
	t.Cleanup(wsHeaderServer.Close)
	headerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, headerName := range forwardedHeaderNames {
			fmt.Fprintln(w, r.Header.Get(headerName))
		}
	}))
	t.Cleanup(headerServer.Close)
	// Start test server that will dump all request headers in the response.
	dumperServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Write(w)
	}))
	t.Cleanup(dumperServer.Close)
	flushServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.(http.Hijacker)
		conn, _, err := h.Hijack()
		require.NoError(t, err)
		defer conn.Close()
		data := "HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"05\r\n" +
			"hello\r\n"
		fmt.Fprint(conn, data)
		time.Sleep(500 * time.Millisecond)
		data = "05\r\n" +
			"world\r\n" +
			"0\r\n" +
			"\r\n"
		fmt.Fprint(conn, data)
	}))
	t.Cleanup(flushServer.Close)

	p.rootAppURI = rootServer.URL
	p.rootWSAppURI = rootWSServer.URL
	p.rootWSSAppURI = rootWSSServer.URL
	p.rootTCPAppURI = fmt.Sprintf("tcp://%v", rootTCPServer.Addr().String())
	p.leafAppURI = leafServer.URL
	p.leafWSAppURI = leafWSServer.URL
	p.leafWSSAppURI = leafWSSServer.URL
	p.leafTCPAppURI = fmt.Sprintf("tcp://%v", leafTCPServer.Addr().String())
	p.jwtAppURI = jwtServer.URL
	p.headerAppURI = headerServer.URL
	p.wsHeaderAppURI = wsHeaderServer.URL
	p.flushAppURI = flushServer.URL
	p.dumperAppURI = dumperServer.URL

	privateKey, publicKey, err := testauthority.New().GenerateKeyPair()
	require.NoError(t, err)

	// Create a new Teleport instance with passed in configuration.
	rootCfg := helpers.InstanceConfig{
		ClusterName: "example.com",
		HostID:      uuid.New().String(),
		NodeName:    helpers.Host,
		Priv:        privateKey,
		Pub:         publicKey,
		Log:         log,
	}
	if opts.RootClusterListeners != nil {
		rootCfg.Listeners = opts.RootClusterListeners(t, &rootCfg.Fds)
	}
	p.rootCluster = helpers.NewInstance(t, rootCfg)

	// Create a new Teleport instance with passed in configuration.
	leafCfg := helpers.InstanceConfig{
		ClusterName: "leaf.example.com",
		HostID:      uuid.New().String(),
		NodeName:    helpers.Host,
		Priv:        privateKey,
		Pub:         publicKey,
		Log:         log,
	}
	if opts.LeafClusterListeners != nil {
		leafCfg.Listeners = opts.LeafClusterListeners(t, &leafCfg.Fds)
	}
	p.leafCluster = helpers.NewInstance(t, leafCfg)

	rcConf := service.MakeDefaultConfig()
	rcConf.Console = nil
	rcConf.Log = log
	rcConf.DataDir = t.TempDir()
	rcConf.Auth.Enabled = true
	rcConf.Auth.Preference.SetSecondFactor("off")
	rcConf.Proxy.Enabled = true
	rcConf.Proxy.DisableWebService = false
	rcConf.Proxy.DisableWebInterface = true
	rcConf.SSH.Enabled = false
	rcConf.Apps.Enabled = false
	rcConf.CircuitBreakerConfig = breaker.NoopBreakerConfig()
	if opts.RootConfig != nil {
		opts.RootConfig(rcConf)
	}

	lcConf := service.MakeDefaultConfig()
	lcConf.Console = nil
	lcConf.Log = log
	lcConf.DataDir = t.TempDir()
	lcConf.Auth.Enabled = true
	lcConf.Auth.Preference.SetSecondFactor("off")
	lcConf.Proxy.Enabled = true
	lcConf.Proxy.DisableWebService = false
	lcConf.Proxy.DisableWebInterface = true
	lcConf.SSH.Enabled = false
	lcConf.Apps.Enabled = false
	lcConf.CircuitBreakerConfig = breaker.NoopBreakerConfig()
	if opts.RootConfig != nil {
		opts.RootConfig(lcConf)
	}

	err = p.leafCluster.CreateEx(t, p.rootCluster.Secrets.AsSlice(), lcConf)
	require.NoError(t, err)
	err = p.rootCluster.CreateEx(t, p.leafCluster.Secrets.AsSlice(), rcConf)
	require.NoError(t, err)

	err = p.leafCluster.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.leafCluster.StopAll()) })
	err = p.rootCluster.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.rootCluster.StopAll()) })

	// At least one rootAppServer should start during the setup
	rootAppServersCount := 1
	p.rootAppServers = p.startRootAppServers(t, rootAppServersCount, opts.ExtraRootApps)

	// At least one leafAppServer should start during the setup
	leafAppServersCount := 1
	p.leafAppServers = p.startLeafAppServers(t, leafAppServersCount, opts.ExtraLeafApps)

	// Create user for tests.
	p.initUser(t, opts)

	// Create Web UI session.
	p.initWebSession(t)

	// Initialize cert pool with root CA's.
	p.initCertPool(t)

	// Initialize Teleport client with the user's credentials.
	p.initTeleportClient(t)

	return p
}

var forwardedHeaderNames = []string{
	teleport.AppJWTHeader,
	teleport.AppCFHeader,
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Forwarded-For",
}

// waitAppServerTunnel waits for application server tunnel connections.
func waitAppServerTunnel(t *testing.T, tunnel reversetunnel.Server, clusterName, serverUUID string) {
	t.Helper()
	cluster, err := tunnel.GetSite(clusterName)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		conn, err := cluster.Dial(reversetunnel.DialParams{
			From:     &utils.NetAddr{AddrNetwork: "tcp", Addr: "@web-proxy"},
			To:       &utils.NetAddr{AddrNetwork: "tcp", Addr: reversetunnel.LocalNode},
			ServerID: fmt.Sprintf("%v.%v", serverUUID, clusterName),
			ConnType: types.AppTunnel,
		})
		if err != nil {
			return false
		}

		require.NoError(t, conn.Close())
		return true
	}, 10*time.Second, time.Second)
}

type appAccessTestFunc func(*Pack, *testing.T)

func bind(p *Pack, fn appAccessTestFunc) func(*testing.T) {
	return func(t *testing.T) {
		fn(p, t)
	}
}

// newTCPServer starts accepting TCP connections and serving them using the
// provided handler. Handlers are expected to close client connections.
// Returns the TCP listener.
func newTCPServer(t *testing.T, handleConn func(net.Conn)) net.Listener {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := listener.Accept()
			if err == nil {
				go handleConn(conn)
			}
			if err != nil && !utils.IsOKNetworkError(err) {
				t.Error(err)
				return
			}
		}
	}()

	return listener
}
