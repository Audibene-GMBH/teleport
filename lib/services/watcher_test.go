/*
Copyright 2021 Gravitational, Inc.

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

package services_test

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/tlsca"
)

var _ types.Events = (*errorWatcher)(nil)

type errorWatcher struct {
}

func (e errorWatcher) NewWatcher(context.Context, types.Watch) (types.Watcher, error) {
	return nil, errors.New("watcher error")
}

var _ services.ProxyGetter = (*nopProxyGetter)(nil)

type nopProxyGetter struct {
}

func (n nopProxyGetter) GetProxies() ([]types.Server, error) {
	return nil, nil
}

func TestResourceWatcher_Backoff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	w, err := services.NewProxyWatcher(ctx, services.ProxyWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:      "test",
			Clock:          clock,
			MaxRetryPeriod: defaults.MaxWatcherBackoff,
			Client:         &errorWatcher{},
			ResetC:         make(chan time.Duration, 5),
		},
		ProxyGetter: &nopProxyGetter{},
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)

	step := w.MaxRetryPeriod / 5.0
	for i := 0; i < 5; i++ {
		// wait for watcher to reload
		select {
		case duration := <-w.ResetC:
			stepMin := step * time.Duration(i) / 2
			stepMax := step * time.Duration(i+1)

			require.GreaterOrEqual(t, duration, stepMin)
			require.LessOrEqual(t, duration, stepMax)

			// wait for watcher to get to retry.After
			clock.BlockUntil(1)

			// add some extra to the duration to ensure the retry occurs
			clock.Advance(w.MaxRetryPeriod)
		case <-time.After(time.Minute):
			t.Fatalf("timeout waiting for reset")
		}
	}
}

func TestProxyWatcher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
	})
	require.NoError(t, err)

	type client struct {
		services.Presence
		types.Events
	}

	presence := local.NewPresenceService(bk)
	w, err := services.NewProxyWatcher(ctx, services.ProxyWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:      "test",
			MaxRetryPeriod: 200 * time.Millisecond,
			Client: &client{
				Presence: presence,
				Events:   local.NewEventsService(bk, nil),
			},
		},
		ProxiesC: make(chan []types.Server, 10),
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)

	// Since no proxy is yet present, the ProxyWatcher should immediately
	// yield back to its retry loop.
	select {
	case <-w.ResetC:
	case <-time.After(time.Second):
		t.Fatalf("Timeout waiting for ProxyWatcher reset.")
	}

	// Add a proxy server.
	proxy := newProxyServer(t, "proxy1", "127.0.0.1:2023")
	require.NoError(t, presence.UpsertProxy(proxy))

	// The first event is always the current list of proxies.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 1)
		require.Empty(t, resourceDiff(changeset[0], proxy))
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the first event.")
	}

	// Add a second proxy.
	proxy2 := newProxyServer(t, "proxy2", "127.0.0.1:2023")
	require.NoError(t, presence.UpsertProxy(proxy2))

	// Watcher should detect the proxy list change.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 2)
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}

	// Delete the first proxy.
	require.NoError(t, presence.DeleteProxy(proxy.GetName()))

	// Watcher should detect the proxy list change.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 1)
		require.Empty(t, resourceDiff(changeset[0], proxy2))
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}
}

func newProxyServer(t *testing.T, name, addr string) types.Server {
	s, err := types.NewServer(name, types.KindProxy, types.ServerSpecV2{
		Addr:       addr,
		PublicAddr: addr,
	})
	require.NoError(t, err)
	return s
}

func TestLockWatcher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            clock,
	})
	require.NoError(t, err)

	type client struct {
		services.Access
		types.Events
	}

	access := local.NewAccessService(bk)
	w, err := services.NewLockWatcher(ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:      "test",
			MaxRetryPeriod: 200 * time.Millisecond,
			Client: &client{
				Access: access,
				Events: local.NewEventsService(bk, nil),
			},
			Clock: clock,
		},
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)

	// Subscribe to lock watcher updates.
	target := types.LockTarget{Node: "node"}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target))
	sub, err := w.Subscribe(ctx, target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sub.Close()) })

	// Add an *expired* lock matching the subscription target.
	pastTime := clock.Now().Add(-time.Minute)
	lock, err := types.NewLock("test-lock", types.LockSpecV2{
		Target:  target,
		Expires: &pastTime,
	})
	require.NoError(t, err)
	require.NoError(t, access.UpsertLock(ctx, lock))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(time.Second):
	}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target))

	// Update the lock so it becomes in force.
	futureTime := clock.Now().Add(time.Minute)
	lock.SetLockExpiry(&futureTime)
	require.NoError(t, access.UpsertLock(ctx, lock))
	select {
	case event := <-sub.Events():
		require.Equal(t, types.OpPut, event.Type)
		receivedLock, ok := event.Resource.(types.Lock)
		require.True(t, ok)
		require.Empty(t, resourceDiff(receivedLock, lock))
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}
	expectLockInForce(t, lock, w.CheckLockInForce(constants.LockingModeBestEffort, target))

	// Delete the lock.
	require.NoError(t, access.DeleteLock(ctx, lock.GetName()))
	select {
	case event := <-sub.Events():
		require.Equal(t, types.OpDelete, event.Type)
		require.Equal(t, event.Resource.GetName(), lock.GetName())
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target))

	// Add a lock matching a different target.
	target2 := types.LockTarget{User: "user"}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target2))
	lock2, err := types.NewLock("test-lock2", types.LockSpecV2{
		Target: target2,
	})
	require.NoError(t, err)
	require.NoError(t, access.UpsertLock(ctx, lock2))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(time.Second):
	}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target))
	expectLockInForce(t, lock2, w.CheckLockInForce(constants.LockingModeBestEffort, target2))
}

func TestLockWatcherSubscribeWithEmptyTarget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            clock,
	})
	require.NoError(t, err)

	type client struct {
		services.Access
		types.Events
	}

	access := local.NewAccessService(bk)
	w, err := services.NewLockWatcher(ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:      "test",
			MaxRetryPeriod: 200 * time.Millisecond,
			Client: &client{
				Access: access,
				Events: local.NewEventsService(bk, nil),
			},
			Clock: clock,
		},
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	select {
	case <-w.LoopC:
	case <-time.After(15 * time.Second):
		t.Fatal("Timeout waiting for LockWatcher loop.")
	}

	// Subscribe to lock watcher updates with an empty target.
	target := types.LockTarget{Node: "node"}
	sub, err := w.Subscribe(ctx, target, types.LockTarget{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sub.Close()) })

	// Add a lock matching one of the subscription targets.
	lock, err := types.NewLock("test-lock", types.LockSpecV2{
		Target: target,
	})
	require.NoError(t, err)
	require.NoError(t, access.UpsertLock(ctx, lock))
	select {
	case event := <-sub.Events():
		require.Equal(t, types.OpPut, event.Type)
		receivedLock, ok := event.Resource.(types.Lock)
		require.True(t, ok)
		require.Empty(t, resourceDiff(receivedLock, lock))
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}

	// Add a lock matching *none* of the subscription targets.
	target2 := types.LockTarget{User: "user"}
	lock2, err := types.NewLock("test-lock2", types.LockSpecV2{
		Target: target2,
	})
	require.NoError(t, err)
	require.NoError(t, access.UpsertLock(ctx, lock2))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(time.Second):
	}
}

func TestLockWatcherStale(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            clock,
	})
	require.NoError(t, err)

	type client struct {
		services.Access
		types.Events
	}

	access := local.NewAccessService(bk)
	events := &withUnreliability{Events: local.NewEventsService(bk, nil)}
	w, err := services.NewLockWatcher(ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:      "test",
			MaxRetryPeriod: 200 * time.Millisecond,
			Client: &client{
				Access: access,
				Events: events,
			},
			Clock: clock,
		},
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	select {
	case <-w.LoopC:
	case <-time.After(15 * time.Second):
		t.Fatal("Timeout waiting for LockWatcher loop.")
	}

	// Subscribe to lock watcher updates.
	target := types.LockTarget{Node: "node"}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target))
	require.NoError(t, w.CheckLockInForce(constants.LockingModeStrict, target))
	sub, err := w.Subscribe(ctx, target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sub.Close()) })

	// Close the underlying watcher. Until LockMaxStaleness is exceeded, no error
	// should be returned.
	events.setUnreliable(true)
	bk.CloseWatchers()
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(2 * time.Second):
	}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target))
	require.NoError(t, w.CheckLockInForce(constants.LockingModeStrict, target))

	// Advance the clock to exceed LockMaxStaleness.
	clock.Advance(defaults.LockMaxStaleness + time.Second)
	select {
	case event := <-sub.Events():
		require.Equal(t, types.OpUnreliable, event.Type)
	case <-sub.Done():
		t.Fatal("Lock watcher subscription has unexpectedly exited.")
	case <-time.After(15 * time.Second):
		t.Fatal("Timeout waiting for OpUnreliable.")
	}
	require.NoError(t, w.CheckLockInForce(constants.LockingModeBestEffort, target))
	expectLockInForce(t, nil, w.CheckLockInForce(constants.LockingModeStrict, target))

	// Add a lock matching the subscription target.
	lock, err := types.NewLock("test-lock", types.LockSpecV2{
		Target: target,
	})
	require.NoError(t, err)
	require.NoError(t, access.UpsertLock(ctx, lock))

	// Make the event stream reliable again. That should broadcast any matching
	// locks added in the meantime.
	events.setUnreliable(false)
	clock.Advance(time.Second)
ExpectPut:
	for {
		select {
		case event := <-sub.Events():
			// There might be additional OpUnreliable events in the queue.
			if event.Type == types.OpUnreliable {
				continue ExpectPut
			}
			require.Equal(t, types.OpPut, event.Type)
			receivedLock, ok := event.Resource.(types.Lock)
			require.True(t, ok)
			require.Empty(t, resourceDiff(receivedLock, lock))
			break ExpectPut
		case <-sub.Done():
			t.Fatal("Lock watcher subscription has unexpectedly exited.")
		case <-time.After(15 * time.Second):
			t.Fatal("Timeout waiting for OpPut.")
		}
	}
	expectLockInForce(t, lock, w.CheckLockInForce(constants.LockingModeBestEffort, target))
	expectLockInForce(t, lock, w.CheckLockInForce(constants.LockingModeStrict, target))
}

type withUnreliability struct {
	types.Events
	rw         sync.RWMutex
	unreliable bool
}

func (e *withUnreliability) setUnreliable(u bool) {
	e.rw.Lock()
	defer e.rw.Unlock()
	e.unreliable = u
}

func (e *withUnreliability) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	e.rw.RLock()
	defer e.rw.RUnlock()
	if e.unreliable {
		return nil, trace.ConnectionProblem(nil, "")
	}
	return e.Events.NewWatcher(ctx, watch)
}

func expectLockInForce(t *testing.T, expectedLock types.Lock, lockErr error) {
	require.Error(t, lockErr)
	if expectedLock != nil {
		require.Empty(t, resourceDiff(expectedLock, lockErr.(trace.Error).GetFields()["lock-in-force"].(types.Lock)))
	}
}

func resourceDiff(res1, res2 types.Resource) string {
	return cmp.Diff(res1, res2,
		cmpopts.IgnoreFields(types.Metadata{}, "ID"),
		cmpopts.EquateEmpty())
}

func caDiff(ca1, ca2 types.CertAuthority) string {
	return cmp.Diff(ca1, ca2,
		cmpopts.IgnoreFields(types.Metadata{}, "ID"),
		cmpopts.IgnoreFields(types.CertAuthoritySpecV2{}, "CheckingKeys", "TLSKeyPairs", "JWTKeyPairs"),
		cmpopts.IgnoreFields(types.SSHKeyPair{}, "PrivateKey"),
		cmpopts.IgnoreFields(types.TLSKeyPair{}, "Key"),
		cmpopts.IgnoreFields(types.JWTKeyPair{}, "PrivateKey"),
		cmpopts.EquateEmpty(),
	)
}

func TestCertAuthorityWatcher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            clock,
	})
	require.NoError(t, err)

	type client struct {
		services.Trust
		types.Events
	}

	caService := local.NewCAService(bk)
	w, err := services.NewCertAuthorityWatcher(ctx, services.CertAuthorityWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:      "test",
			MaxRetryPeriod: 200 * time.Millisecond,
			Client: &client{
				Trust:  caService,
				Events: local.NewEventsService(bk, nil),
			},
			Clock: clock,
		},
		Types: []types.CertAuthType{types.HostCA, types.UserCA},
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)

	target := services.CertAuthorityTarget{ClusterName: "test"}
	sub, err := w.Subscribe(ctx, target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sub.Close()) })

	// create a CA for the cluster and a type we are filtering for
	// and ensure we receive the event
	ca := newCertAuthority(t, "test", types.HostCA)
	require.NoError(t, caService.UpsertCertAuthority(ca))
	select {
	case event := <-sub.Events():
		caFromEvent, ok := event.Resource.(types.CertAuthority)
		require.True(t, ok)
		require.Empty(t, caDiff(ca, caFromEvent))
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}

	// create a CA with a type we are filtering for another cluster that we are NOT filtering for
	// and ensure that we DO NOT receive the event
	require.NoError(t, caService.UpsertCertAuthority(newCertAuthority(t, "unknown", types.UserCA)))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("CA watcher subscription has unexpectedly exited.")
	case <-time.After(time.Second):
	}

	// create a CA for the cluster and a type we are filtering for
	// and ensure we receive the event
	ca2 := newCertAuthority(t, "test", types.UserCA)
	require.NoError(t, caService.UpsertCertAuthority(ca2))
	select {
	case event := <-sub.Events():
		caFromEvent, ok := event.Resource.(types.CertAuthority)
		require.True(t, ok)
		require.Empty(t, caDiff(ca2, caFromEvent))
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}

	// delete a CA with type being watched in the cluster we are filtering for
	// and ensure we receive the event
	require.NoError(t, caService.DeleteCertAuthority(ca.GetID()))
	select {
	case event := <-sub.Events():
		require.Equal(t, types.KindCertAuthority, event.Resource.GetKind())
		require.Equal(t, string(types.HostCA), event.Resource.GetSubKind())
		require.Equal(t, "test", event.Resource.GetName())
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}

	// create a CA with a type we are NOT filtering for but for a cluster we are filtering for
	// and ensure we DO NOT receive the event
	signer := newCertAuthority(t, "test", types.JWTSigner)
	require.NoError(t, caService.UpsertCertAuthority(signer))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("CA watcher subscription has unexpectedly exited.")
	case <-time.After(time.Second):
	}

	// delete a CA with a name we are filtering for but a type we are NOT filtering for
	// and ensure we do NOT receive the event
	require.NoError(t, caService.DeleteCertAuthority(signer.GetID()))
	select {
	case event := <-sub.Events():
		t.Fatalf("Unexpected event: %v.", event)
	case <-sub.Done():
		t.Fatal("CA watcher subscription has unexpectedly exited.")
	case <-time.After(time.Second):
	}
}

func newCertAuthority(t *testing.T, name string, caType types.CertAuthType) types.CertAuthority {
	ta := testauthority.New()
	priv, pub, err := ta.GenerateKeyPair("")
	require.NoError(t, err)

	// CA for cluster1 with 1 key pair.
	key, cert, err := tlsca.GenerateSelfSignedCA(pkix.Name{CommonName: name}, nil, time.Minute)
	require.NoError(t, err)

	ca, err := types.NewCertAuthority(types.CertAuthoritySpecV2{
		Type:        caType,
		ClusterName: name,
		ActiveKeys: types.CAKeySet{
			SSH: []*types.SSHKeyPair{
				{
					PrivateKey:     priv,
					PrivateKeyType: types.PrivateKeyType_RAW,
					PublicKey:      pub,
				},
			},
			TLS: []*types.TLSKeyPair{
				{
					Cert: cert,
					Key:  key,
				},
			},
			JWT: []*types.JWTKeyPair{
				{
					PublicKey:  []byte(fixtures.JWTSignerPublicKey),
					PrivateKey: []byte(fixtures.JWTSignerPrivateKey),
				},
			},
		},
		Roles:      nil,
		SigningAlg: types.CertAuthoritySpecV2_RSA_SHA2_256,
	})
	require.NoError(t, err)
	return ca
}

func TestNodeWatcher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
	})
	require.NoError(t, err)

	type client struct {
		services.Presence
		types.Events
	}

	presence := local.NewPresenceService(bk)
	w, err := services.NewNodeWatcher(ctx, services.NodeWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: "test",
			Client: &client{
				Presence: presence,
				Events:   local.NewEventsService(bk, nil),
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(w.Close)

	// Add some node servers.
	nodes := make([]types.Server, 0, 5)
	for i := 0; i < 5; i++ {
		node := newNodeServer(t, fmt.Sprintf("node%d", i), "127.0.0.1:2023", i%2 == 0)
		_, err = presence.UpsertNode(ctx, node)
		require.NoError(t, err)
		nodes = append(nodes, node)
	}

	require.Eventually(t, func() bool {
		filtered := w.GetNodes(func(n services.Node) bool {
			return true
		})
		return len(filtered) == len(nodes)
	}, time.Second, time.Millisecond, "Timeout waiting for watcher to receive nodes.")

	require.Len(t, w.GetNodes(func(n services.Node) bool { return n.GetUseTunnel() }), 3)

	require.NoError(t, presence.DeleteNode(ctx, apidefaults.Namespace, nodes[0].GetName()))

	require.Eventually(t, func() bool {
		filtered := w.GetNodes(func(n services.Node) bool {
			return true
		})
		return len(filtered) == len(nodes)-1
	}, time.Second, time.Millisecond, "Timeout waiting for watcher to receive nodes.")

	require.Empty(t, w.GetNodes(func(n services.Node) bool { return n.GetName() == nodes[0].GetName() }))

}

func newNodeServer(t *testing.T, name, addr string, tunnel bool) types.Server {
	s, err := types.NewServer(name, types.KindNode, types.ServerSpecV2{
		Addr:       addr,
		PublicAddr: addr,
		UseTunnel:  tunnel,
	})
	require.NoError(t, err)
	return s
}
