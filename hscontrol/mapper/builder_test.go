package mapper

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func TestMapResponseBuilder_UserPoolHostRoute(t *testing.T) {
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: t.TempDir() + "/headscale.db"},
		},
		PrefixV4: &p4, PrefixV6: &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}
	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	user := s.CreateUserForTest("alice")
	require.NoError(t, s.UpdatePolicyManagerUsersForTest())
	_, _, err = s.UpdatePolicy([]byte(`{
		"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24","fd42:1::/64"]}],
		"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]
	}`))
	require.NoError(t, err)

	var nodes []types.NodeView
	for _, os := range []string{"linux", "android"} {
		authKey, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
		require.NoError(t, err)
		node, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:    &tailcfg.RegisterResponseAuth{AuthKey: authKey.Key},
			NodeKey: key.NewNode().Public(), Hostinfo: &tailcfg.Hostinfo{Hostname: os, OS: os},
		}, key.NewMachine().Public())
		require.NoError(t, err)
		nodes = append(nodes, node)
	}
	router, android := nodes[0], nodes[1]
	route := netip.MustParsePrefix("100.84.4.113/32")
	_, err = s.UpdateNodeFromMapRequest(router.ID(), tailcfg.MapRequest{
		NodeKey:  router.NodeKey(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "linux", OS: "linux", RoutableIPs: []netip.Prefix{route}},
	})
	require.NoError(t, err)
	_, _, err = s.SetApprovedRoutes(router.ID(), []netip.Prefix{route})
	require.NoError(t, err)
	s.Connect(router.ID())
	router, ok := s.GetNodeByID(router.ID())
	require.True(t, ok)
	m := &mapper{cfg: cfg, state: s}

	for _, enabled := range []bool{true, false, true} {
		if !enabled {
			_, _, err = s.UpdatePolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
		} else {
			_, _, err = s.UpdatePolicy([]byte(`{
				"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24","fd42:1::/64"]}],
				"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]
			}`))
		}
		require.NoError(t, err)
		resp, err := m.NewMapResponseBuilder(android.ID()).
			WithCapabilityVersion(tailcfg.CurrentCapabilityVersion).
			WithPeers(views.SliceOf([]types.NodeView{router})).Build()
		require.NoError(t, err)
		require.Len(t, resp.Peers, 1)
		self, err := m.NewMapResponseBuilder(router.ID()).
			WithCapabilityVersion(tailcfg.CurrentCapabilityVersion).WithSelfNode().Build()
		require.NoError(t, err)
		if enabled {
			assert.Contains(t, resp.Peers[0].AllowedIPs, route)
			assert.Contains(t, resp.Peers[0].PrimaryRoutes, route)
			assert.Contains(t, self.Node.PrimaryRoutes, route)
		} else {
			assert.NotContains(t, resp.Peers[0].AllowedIPs, route)
			assert.NotContains(t, resp.Peers[0].PrimaryRoutes, route)
			assert.NotContains(t, self.Node.PrimaryRoutes, route)
		}
	}
}

func TestMapResponseBuilder_Basic(t *testing.T) {
	cfg := &types.Config{
		BaseDomain: "example.com",
		LogTail: types.LogTailConfig{
			Enabled: true,
		},
	}

	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID)

	// Test basic builder creation
	assert.NotNil(t, builder)
	assert.Equal(t, nodeID, builder.nodeID)
	assert.NotNil(t, builder.resp)
	assert.False(t, builder.resp.KeepAlive)
	assert.NotNil(t, builder.resp.ControlTime)
	assert.WithinDuration(t, time.Now(), *builder.resp.ControlTime, time.Second)
}

func TestMapResponseBuilder_WithCapabilityVersion(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	capVer := tailcfg.CapabilityVersion(42)

	builder := m.NewMapResponseBuilder(nodeID).
		WithCapabilityVersion(capVer)

	assert.Equal(t, capVer, builder.capVer)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_WithDomain(t *testing.T) {
	domain := "test.example.com"
	cfg := &types.Config{
		ServerURL:  "https://test.example.com",
		BaseDomain: domain,
	}

	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithDomain()

	assert.Equal(t, domain, builder.resp.Domain)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_WithCollectServicesDisabled(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithCollectServicesDisabled()

	value, isSet := builder.resp.CollectServices.Get()
	assert.True(t, isSet)
	assert.False(t, value)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_WithDebugConfig(t *testing.T) {
	tests := []struct {
		name           string
		logTailEnabled bool
		expected       *tailcfg.Debug
	}{
		{
			// Enabled sends no Debug, so the wire matches a server that never
			// touches client logging.
			name:           "LogTail enabled",
			logTailEnabled: true,
			expected:       nil,
		},
		{
			name:           "LogTail disabled",
			logTailEnabled: false,
			expected:       &tailcfg.Debug{DisableLogTail: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &types.Config{
				LogTail: types.LogTailConfig{
					Enabled: tt.logTailEnabled,
				},
			}
			mockState := &state.State{}
			m := &mapper{
				cfg:   cfg,
				state: mockState,
			}

			nodeID := types.NodeID(1)

			builder := m.NewMapResponseBuilder(nodeID).
				WithDebugConfig()

			assert.Equal(t, tt.expected, builder.resp.Debug)
			assert.False(t, builder.hasErrors())
		})
	}
}

func TestMapResponseBuilder_WithPeerChangedPatch(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	changes := []*tailcfg.PeerChange{
		{
			NodeID:     123,
			DERPRegion: 1,
		},
		{
			NodeID:     456,
			DERPRegion: 2,
		},
	}

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeerChangedPatch(changes)

	assert.Equal(t, changes, builder.resp.PeersChangedPatch)
	assert.False(t, builder.hasErrors())
}

// TestMapResponseBuilder_WithPeerChangedPatchDropsUnencodableExpiry proves a
// patch whose key expiry json.Marshal refuses is left out, as buildTailPeers
// leaves out such a peer, instead of failing the viewer's whole response.
func TestMapResponseBuilder_WithPeerChangedPatchDropsUnencodableExpiry(t *testing.T) {
	m := &mapper{cfg: &types.Config{}, state: &state.State{}}

	latest := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	beyond := latest.Add(time.Second)
	changes := []*tailcfg.PeerChange{
		{NodeID: 123, KeyExpiry: &beyond},
		{NodeID: 456, KeyExpiry: &latest},
	}

	builder := m.NewMapResponseBuilder(types.NodeID(1)).WithPeerChangedPatch(changes)
	assert.Equal(t, changes[1:], builder.resp.PeersChangedPatch)

	_, err := json.Marshal(builder.resp)
	require.NoError(t, err)
}

func TestMapResponseBuilder_WithPeersRemoved(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	removedID1 := types.NodeID(123)
	removedID2 := types.NodeID(456)

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeersRemoved(removedID1, removedID2)

	expected := []tailcfg.NodeID{
		removedID1.NodeID(),
		removedID2.NodeID(),
	}
	assert.Equal(t, expected, builder.resp.PeersRemoved)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_ErrorHandling(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	// Simulate an error in the builder
	builder := m.NewMapResponseBuilder(nodeID)
	builder.addError(assert.AnError)

	// All subsequent calls should continue to work and accumulate errors
	result := builder.
		WithDomain().
		WithCollectServicesDisabled().
		WithDebugConfig()

	assert.True(t, result.hasErrors())
	assert.Len(t, result.errs, 1)
	assert.Equal(t, assert.AnError, result.errs[0])

	// Build should return the error
	data, err := result.Build()
	assert.Nil(t, data)
	assert.Error(t, err)
}

func TestMapResponseBuilder_ChainedCalls(t *testing.T) {
	domain := "chained.example.com"
	cfg := &types.Config{
		ServerURL:  "https://chained.example.com",
		BaseDomain: domain,
		LogTail: types.LogTailConfig{
			Enabled: false,
		},
	}

	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	capVer := tailcfg.CapabilityVersion(99)

	builder := m.NewMapResponseBuilder(nodeID).
		WithCapabilityVersion(capVer).
		WithDomain().
		WithCollectServicesDisabled().
		WithDebugConfig()

	// Verify all fields are set correctly
	assert.Equal(t, capVer, builder.capVer)
	assert.Equal(t, domain, builder.resp.Domain)
	value, isSet := builder.resp.CollectServices.Get()
	assert.True(t, isSet)
	assert.False(t, value)
	assert.NotNil(t, builder.resp.Debug)
	assert.True(t, builder.resp.Debug.DisableLogTail)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_MultipleWithPeersRemoved(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)
	removedID1 := types.NodeID(100)
	removedID2 := types.NodeID(200)

	// Test calling WithPeersRemoved multiple times
	builder := m.NewMapResponseBuilder(nodeID).
		WithPeersRemoved(removedID1).
		WithPeersRemoved(removedID2)

	// Second call should overwrite the first
	expected := []tailcfg.NodeID{removedID2.NodeID()}
	assert.Equal(t, expected, builder.resp.PeersRemoved)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_EmptyPeerChangedPatch(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeerChangedPatch([]*tailcfg.PeerChange{})

	assert.Empty(t, builder.resp.PeersChangedPatch)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_NilPeerChangedPatch(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	builder := m.NewMapResponseBuilder(nodeID).
		WithPeerChangedPatch(nil)

	assert.Nil(t, builder.resp.PeersChangedPatch)
	assert.False(t, builder.hasErrors())
}

func TestMapResponseBuilder_MultipleErrors(t *testing.T) {
	cfg := &types.Config{}
	mockState := &state.State{}
	m := &mapper{
		cfg:   cfg,
		state: mockState,
	}

	nodeID := types.NodeID(1)

	// Create a builder and add multiple errors
	builder := m.NewMapResponseBuilder(nodeID)
	builder.addError(assert.AnError)
	builder.addError(assert.AnError)
	builder.addError(nil) // This should be ignored

	// All subsequent calls should continue to work
	result := builder.
		WithDomain().
		WithCollectServicesDisabled()

	assert.True(t, result.hasErrors())
	assert.Len(t, result.errs, 2) // nil error should be ignored

	// Build should return a multierr
	data, err := result.Build()
	require.Nil(t, data)
	require.Error(t, err)

	// The error should contain information about multiple errors
	assert.Contains(t, err.Error(), "multiple errors")
}
