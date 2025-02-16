/*
Copyright 2018-2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"github.com/gravitational/teleport"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/multiplexer"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// TLSServerConfig is a configuration for TLS server
type TLSServerConfig struct {
	// ForwarderConfig is a config of a forwarder
	ForwarderConfig
	// TLS is a base TLS configuration
	TLS *tls.Config
	// LimiterConfig is limiter config
	LimiterConfig limiter.Config
	// AccessPoint is caching access point
	AccessPoint auth.ReadKubernetesAccessPoint
	// OnHeartbeat is a callback for kubernetes_service heartbeats.
	OnHeartbeat func(error)
	// GetRotation returns the certificate rotation state.
	GetRotation services.RotationGetter
	// ConnectedProxyGetter gets the proxies teleport is connected to.
	ConnectedProxyGetter *reversetunnel.ConnectedProxyGetter
	// Log is the logger.
	Log log.FieldLogger
}

// CheckAndSetDefaults checks and sets default values
func (c *TLSServerConfig) CheckAndSetDefaults() error {
	if err := c.ForwarderConfig.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if c.TLS == nil {
		return trace.BadParameter("missing parameter TLS")
	}
	c.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	if c.TLS.ClientCAs == nil {
		return trace.BadParameter("missing parameter TLS.ClientCAs")
	}
	if c.TLS.RootCAs == nil {
		return trace.BadParameter("missing parameter TLS.RootCAs")
	}
	if len(c.TLS.Certificates) == 0 {
		return trace.BadParameter("missing parameter TLS.Certificates")
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("missing parameter AccessPoint")
	}
	if c.Log == nil {
		c.Log = log.New()
	}
	if c.ConnectedProxyGetter == nil {
		c.ConnectedProxyGetter = reversetunnel.NewConnectedProxyGetter()
	}

	return nil
}

// TLSServer is TLS auth server
type TLSServer struct {
	*http.Server
	// TLSServerConfig is TLS server configuration used for auth server
	TLSServerConfig
	fwd          *Forwarder
	mu           sync.Mutex
	listener     net.Listener
	heartbeats   map[string]*srv.Heartbeat
	closeContext context.Context
	closeFunc    context.CancelFunc
}

// NewTLSServer returns new unstarted TLS server
func NewTLSServer(cfg TLSServerConfig) (*TLSServer, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	// limiter limits requests by frequency and amount of simultaneous
	// connections per client
	limiter, err := limiter.NewLimiter(cfg.LimiterConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	fwd, err := NewForwarder(cfg.ForwarderConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// authMiddleware authenticates request assuming TLS client authentication
	// adds authentication information to the context
	// and passes it to the API server
	authMiddleware := &auth.Middleware{
		AccessPoint:   cfg.AccessPoint,
		AcceptedUsage: []string{teleport.UsageKubeOnly},
	}
	authMiddleware.Wrap(fwd)
	// Wrap sets the next middleware in chain to the authMiddleware
	limiter.WrapHandle(authMiddleware)
	// force client auth if given
	cfg.TLS.ClientAuth = tls.VerifyClientCertIfGiven

	server := &TLSServer{
		fwd:             fwd,
		TLSServerConfig: cfg,
		Server: &http.Server{
			Handler:           limiter,
			ReadHeaderTimeout: apidefaults.DefaultDialTimeout * 2,
			TLSConfig:         cfg.TLS,
		},
		heartbeats: make(map[string]*srv.Heartbeat),
	}
	server.TLS.GetConfigForClient = server.GetConfigForClient
	server.closeContext, server.closeFunc = context.WithCancel(cfg.Context)

	return server, nil
}

// Serve takes TCP listener, upgrades to TLS using config and starts serving
func (t *TLSServer) Serve(listener net.Listener) error {
	// Wrap listener with a multiplexer to get Proxy Protocol support.
	mux, err := multiplexer.New(multiplexer.Config{
		Context:             t.Context,
		Listener:            listener,
		Clock:               t.Clock,
		EnableProxyProtocol: true,
		ID:                  t.Component,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	go mux.Serve()
	defer mux.Close()

	t.mu.Lock()
	t.listener = mux.TLS()
	if err = http2.ConfigureServer(t.Server, &http2.Server{}); err != nil {
		return trace.Wrap(err)
	}
	t.mu.Unlock()

	// startStaticClusterHeartbeats starts the heartbeat process for static clusters.
	// static clusters can be specified via kubeconfig or clusterName for Teleport agent
	// running in Kubernetes.
	if err := t.startStaticClustersHeartbeat(); err != nil {
		return trace.Wrap(err)
	}

	return t.Server.Serve(tls.NewListener(mux.TLS(), t.TLS))
}

// Close closes the server and cleans up all resources.
func (t *TLSServer) Close() error {
	errs := []error{t.Server.Close()}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, heartbeat := range t.heartbeats {
		errs = append(errs, heartbeat.Close())
	}
	return trace.NewAggregate(errs...)
}

// GetConfigForClient is getting called on every connection
// and server's GetConfigForClient reloads the list of trusted
// local and remote certificate authorities
func (t *TLSServer) GetConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	return auth.WithClusterCAs(t.TLS, t.AccessPoint, t.ClusterName, t.Log)(info)
}

// getServerInfoFunc returns function that the heartbeater uses to report the
// provided cluster to the auth server.
func (t *TLSServer) getServerInfoFunc(cluster types.KubeCluster) func() (types.Resource, error) {
	return func() (types.Resource, error) {
		return t.getServerInfo(cluster)
	}
}

// GetServerInfo returns a services.Server object for heartbeats (aka
// presence).
func (t *TLSServer) getServerInfo(cluster types.KubeCluster) (types.Resource, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var addr string
	if t.TLSServerConfig.ForwarderConfig.PublicAddr != "" {
		addr = t.TLSServerConfig.ForwarderConfig.PublicAddr
	} else if t.listener != nil {
		addr = t.listener.Addr().String()
	}

	// Both proxy and kubernetes services can run in the same instance (same
	// cluster names). Add a name suffix to make them distinct.
	//
	// Note: we *don't* want to add suffix for kubernetes_service!
	// This breaks reverse tunnel routing, which uses server.Name.
	name := cluster.GetName()
	if t.KubeServiceType != KubeService {
		name += "-proxy_service"
	}

	srv, err := types.NewKubernetesServerV3(
		types.Metadata{
			Name:      name,
			Namespace: t.Namespace,
		},
		types.KubernetesServerSpecV3{
			Version:  teleport.Version,
			Hostname: addr,
			HostID:   t.TLSServerConfig.HostID,
			Rotation: t.getRotationState(),
			Cluster:  cluster.Copy(),
			ProxyIDs: t.ConnectedProxyGetter.GetProxyIDs(),
		},
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	srv.SetExpiry(t.Clock.Now().UTC().Add(apidefaults.ServerAnnounceTTL))
	return srv, nil
}

// startHeartbeat starts the registration heartbeat to the auth server.
func (t *TLSServer) startHeartbeat(ctx context.Context, kubeCluster types.KubeCluster) error {
	heartbeat, err := srv.NewHeartbeat(srv.HeartbeatConfig{
		Mode:            srv.HeartbeatModeKube,
		Context:         t.TLSServerConfig.Context,
		Component:       t.TLSServerConfig.Component,
		Announcer:       t.TLSServerConfig.AuthClient,
		GetServerInfo:   t.getServerInfoFunc(kubeCluster),
		KeepAlivePeriod: apidefaults.ServerKeepAliveTTL(),
		AnnouncePeriod:  apidefaults.ServerAnnounceTTL/2 + utils.RandomDuration(apidefaults.ServerAnnounceTTL/10),
		ServerTTL:       apidefaults.ServerAnnounceTTL,
		CheckPeriod:     defaults.HeartbeatCheckPeriod,
		Clock:           t.TLSServerConfig.Clock,
		OnHeartbeat:     t.TLSServerConfig.OnHeartbeat,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	go heartbeat.Run()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.heartbeats[kubeCluster.GetName()] = heartbeat
	return nil
}

// getRotationState is a helper to return this server's CA rotation state.
func (t *TLSServer) getRotationState() types.Rotation {
	rotation, err := t.TLSServerConfig.GetRotation(types.RoleKube)
	if err != nil && !trace.IsNotFound(err) {
		t.Log.WithError(err).Warn("Failed to get rotation state.")
	}
	if rotation != nil {
		return *rotation
	}
	return types.Rotation{}
}

func (t *TLSServer) startStaticClustersHeartbeat() error {
	// Start the heartbeat to announce kubernetes_service presence.
	//
	// Only announce when running in an actual kube_server, or when
	// running in proxy_service with local kube credentials. This means that
	// proxy_service will pretend to also be kube_server.
	if t.KubeServiceType == KubeService ||
		t.KubeServiceType == LegacyProxyService {
		log.Debugf("Starting kubernetes_service heartbeats for %q", t.Component)
		for _, cluster := range t.fwd.kubeClusters() {
			if err := t.startHeartbeat(t.closeContext, cluster); err != nil {
				return trace.Wrap(err)
			}
		}
	} else {
		log.Debug("No local kube credentials on proxy, will not start kubernetes_service heartbeats")
	}

	return nil
}
