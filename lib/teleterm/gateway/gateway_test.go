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

package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func TestCLICommandUsesCLICommandProvider(t *testing.T) {
	gateway := Gateway{
		Config: Config{
			TargetName:            "foo",
			TargetSubresourceName: "bar",
			Protocol:              defaults.ProtocolPostgres,
		},
		cliCommandProvider: mockCLICommandProvider{},
		tcpPortAllocator:   &mockTCPPortAllocator{},
	}

	command, err := gateway.CLICommand()
	require.NoError(t, err)

	require.Equal(t, "foo/bar", command)
}

func TestGatewayStart(t *testing.T) {
	hs := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {}))
	t.Cleanup(func() {
		hs.Close()
	})

	gateway, err := New(
		Config{
			TargetName:   "foo",
			TargetURI:    uri.NewClusterURI("bar").AppendDB("foo").String(),
			TargetUser:   "alice",
			Protocol:     defaults.ProtocolPostgres,
			CertPath:     "../../../fixtures/certs/proxy1.pem",
			KeyPath:      "../../../fixtures/certs/proxy1-key.pem",
			Insecure:     true,
			WebProxyAddr: hs.Listener.Addr().String(),
		},
		mockCLICommandProvider{},
		&mockTCPPortAllocator{},
	)
	require.NoError(t, err)
	t.Cleanup(func() { gateway.Close() })
	gatewayAddress := net.JoinHostPort(gateway.LocalAddress, gateway.LocalPort)

	require.NotEmpty(t, gateway.LocalPort)
	require.NotEqual(t, "0", gateway.LocalPort)

	serveErr := make(chan error)

	go func() {
		err := gateway.Serve()
		serveErr <- err
	}()

	blockUntilGatewayAcceptsConnections(t, gatewayAddress)

	err = gateway.Close()
	require.NoError(t, err)
	require.NoError(t, <-serveErr)
}

// TODO: Add a private method called `attachListener` to Gateway. Use it in SetLocalPort and in New.
// Basically before closing the current listener, open a new one. If it errors, return an error and
// if not, close the current listener and attach the new one.
//
// This should simplify the interface that we need to mock as we'll probably need to mock just the
// net package rather than creating a whole new struct with specific methods.
//
// Also, we don't need to open the listener on that port twice.

func TestSetLocalPortStartsListenerOnNewPortIfPortIsFree(t *testing.T) {
	hs := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {}))
	t.Cleanup(func() {
		hs.Close()
	})

	mockTCPPortAllocator := &mockTCPPortAllocator{}

	gateway, err := New(
		Config{
			TargetName:   "foo",
			TargetURI:    uri.NewClusterURI("bar").AppendDB("foo").String(),
			TargetUser:   "alice",
			Protocol:     defaults.ProtocolPostgres,
			CertPath:     "../../../fixtures/certs/proxy1.pem",
			KeyPath:      "../../../fixtures/certs/proxy1-key.pem",
			Insecure:     true,
			WebProxyAddr: hs.Listener.Addr().String(),
		},
		mockCLICommandProvider{},
		mockTCPPortAllocator,
	)
	require.NoError(t, err)
	t.Cleanup(func() { gateway.Close() })
	gatewayAddress := net.JoinHostPort(gateway.LocalAddress, gateway.LocalPort)

	go func() {
		if err := gateway.Serve(); err != nil {
			t.Fatal(err)
		}
	}()

	blockUntilGatewayAcceptsConnections(t, gatewayAddress)

	err = gateway.SetLocalPort("12345")
	require.NoError(t, err)

	require.Equal(t, "12345", gateway.LocalPort)

	// Verify that the gateway is accepting connections on the new listener.
	newGatewayAddress := mockTCPPortAllocator.RecentListener().RealAddr().String()
	blockUntilGatewayAcceptsConnections(t, newGatewayAddress)
}

// func TestSetLocalPortDoesntStopGatewayIfNewPortIsOccupied(t *testing.T) {
// 	hs := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {}))
// 	t.Cleanup(func() {
// 		hs.Close()
// 	})

// 	gateway, err := New(
// 		Config{
// 			TargetName:   "foo",
// 			TargetURI:    uri.NewClusterURI("bar").AppendDB("foo").String(),
// 			TargetUser:   "alice",
// 			Protocol:     defaults.ProtocolPostgres,
// 			CertPath:     "../../../fixtures/certs/proxy1.pem",
// 			KeyPath:      "../../../fixtures/certs/proxy1-key.pem",
// 			Insecure:     true,
// 			WebProxyAddr: hs.Listener.Addr().String(),
// 		},
// 		mockCLICommandProvider{},
// 		mockTCPPortAllocator{portsInUse: []string{"12345"}},
// 	)
// 	originalPort := gateway.LocalPort
// 	require.NoError(t, err)

// 	err = gateway.SetLocalPort("12345")
// 	require.ErrorContains(t, err, "address already in use")
// 	require.Equal(t, originalPort, gateway.LocalPort)

// 	// Verify that the gateway wasn't stopped.
// 	require.NoError(t, gateway.closeContext.Err(),
// 		"Gateway was stopped but it wasn't supposed to be stopped")
// }

type mockCLICommandProvider struct{}

func (m mockCLICommandProvider) GetCommand(gateway *Gateway) (string, error) {
	command := fmt.Sprintf("%s/%s", gateway.TargetName, gateway.TargetSubresourceName)
	return command, nil
}

type mockTCPPortAllocator struct {
	portsInUse    []string
	mockListeners []mockListener
}

// Listen accepts localPort as an argument but creates a listener on a random port. This lets us
// test code that attempt to set the port number to a specific value without risking that the actual
// port on the device running the tests is occupied.
//
// Listen returns a mock listener which forwards all methods to the real listener on the random port
// but its Addr function returns the port that was given as an argument to Listen.
func (m *mockTCPPortAllocator) Listen(localAddress, localPort string) (net.Listener, error) {
	if apiutils.SliceContainsStr(m.portsInUse, localPort) {
		return nil, trace.BadParameter("address already in use")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", "localhost", "0"))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	mockListener := mockListener{
		realListener: listener,
		fakePort:     localPort,
	}

	m.mockListeners = append(m.mockListeners, mockListener)

	return mockListener, nil
}

func (m *mockTCPPortAllocator) RecentListener() *mockListener {
	if len(m.mockListeners) == 0 {
		return nil
	}
	return &m.mockListeners[len(m.mockListeners)-1]
}

// mockListener forwards almost all calls to the real listener. When asked about address, it will
// return the one pointing at the fake port.
//
// This lets us make calls to set the gateway port to a specific port without actually occupying
// those ports on the real system (which would lead to flaky tests otherwise).
type mockListener struct {
	realListener net.Listener
	fakePort     string
}

func (m mockListener) Accept() (net.Conn, error) {
	return m.realListener.Accept()
}

func (m mockListener) Close() error {
	return m.realListener.Close()
}

func (m mockListener) Addr() net.Addr {
	if m.fakePort == "0" {
		return m.realListener.Addr()
	}

	addr, err := net.ResolveTCPAddr("", fmt.Sprintf("%s:%s", "localhost", m.fakePort))

	if err != nil {
		panic(err)
	}

	return addr
}

func (m mockListener) RealAddr() net.Addr {
	return m.realListener.Addr()
}

func blockUntilGatewayAcceptsConnections(t *testing.T, address string) {
	conn, err := net.DialTimeout("tcp", address, time.Second*1)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	require.NoError(t, err)

	out := make([]byte, 1024)
	_, err = conn.Read(out)
	// Our "client" here is going to fail the handshake because it requests an application protocol
	// (typically teleport-<some db protocol>) that the target server (typically
	// httptest.NewTLSServer) doesn't support.
	//
	// So we just expect EOF here. In case of a timeout, this check will fail.
	require.True(t, trace.IsEOF(err), "expected EOF, got %v", err)

	err = conn.Close()
	require.NoError(t, err)
}
