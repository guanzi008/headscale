package v2

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// nodeAttrsTestUsers returns a minimal user set: two passkey-style users on
// different domains, mirroring the production multi-domain shape so user-target
// resolution is exercised across both.
func nodeAttrsTestUsers() types.Users {
	return types.Users{
		{ID: 1, Name: "alice", Email: "alice@example.com"},
		{ID: 2, Name: "bob", Email: "bob@example.org"},
	}
}

// nodeAttrsTestNodes returns a fixed mix of user-owned and tagged nodes used
// by every nodeAttrs unit test. Two user-owned nodes (one per user) and three
// tagged nodes (server, client, prod) so target resolution can be exercised
// across user, group, tag, autogroup, and wildcard alias forms.
func nodeAttrsTestNodes(users types.Users) types.Nodes {
	return types.Nodes{
		{
			ID:        1,
			GivenName: "alice-laptop",
			User:      &users[0],
			UserID:    &users[0].ID,
			IPv4:      ptrAddr("100.64.0.1"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::1"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        2,
			GivenName: "bob-laptop",
			User:      &users[1],
			UserID:    &users[1].ID,
			IPv4:      ptrAddr("100.64.0.2"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::2"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        3,
			GivenName: "server",
			Tags:      []string{"tag:server"},
			IPv4:      ptrAddr("100.64.0.3"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::3"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        4,
			GivenName: "client",
			Tags:      []string{"tag:client"},
			IPv4:      ptrAddr("100.64.0.4"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::4"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        5,
			GivenName: "prod",
			Tags:      []string{"tag:prod"},
			IPv4:      ptrAddr("100.64.0.5"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::5"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
	}
}

const nodeAttrsTagOwners = `"tag:server": ["alice@example.com"],
		"tag:client": ["alice@example.com"],
		"tag:prod":   ["alice@example.com"]`

func TestNodeAttrsCompile(t *testing.T) {
	t.Parallel()

	capMap := func(c nodecap.Cap) tailcfg.NodeCapMap {
		return tailcfg.NodeCapMap{c: nil}
	}

	tests := []struct {
		name string
		// extra is appended inside the policy block alongside tagOwners.
		extra string
		want  map[types.NodeID]tailcfg.NodeCapMap
	}{
		{
			// One unregistered member must not reject the policy (#3513).
			name: "group target with unregistered member hits registered members",
			extra: `"groups": {"group:g": ["alice@example.com", "ghost@example.com"]},
		"nodeAttrs": [{"target": ["group:g"], "attr": ["randomize-client-port"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap("randomize-client-port"),
			},
		},
		{
			name:  "wildcard target hits every node",
			extra: `"nodeAttrs": [{"target": ["*"], "attr": ["randomize-client-port"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(nodecap.RandomizeClientPort),
				2: capMap(nodecap.RandomizeClientPort),
				3: capMap(nodecap.RandomizeClientPort),
				4: capMap(nodecap.RandomizeClientPort),
				5: capMap(nodecap.RandomizeClientPort),
			},
		},
		{
			name:  "user target hits only that user's untagged nodes",
			extra: `"nodeAttrs": [{"target": ["alice@example.com"], "attr": ["randomize-client-port"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(nodecap.RandomizeClientPort),
			},
		},
		{
			name:  "tag target hits only matching tagged nodes",
			extra: `"nodeAttrs": [{"target": ["tag:server"], "attr": ["drive:share", "drive:access"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				3: {
					nodecap.TaildriveShare:  nil,
					nodecap.TaildriveAccess: nil,
				},
			},
		},
		{
			name:  "autogroup:member hits untagged nodes only",
			extra: `"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["randomize-client-port"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(nodecap.RandomizeClientPort),
				2: capMap(nodecap.RandomizeClientPort),
			},
		},
		{
			name:  "autogroup:tagged hits tagged nodes only",
			extra: `"nodeAttrs": [{"target": ["autogroup:tagged"], "attr": ["disable-captive-portal-detection"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				3: capMap(nodecap.DisableCaptivePortalDetection),
				4: capMap(nodecap.DisableCaptivePortalDetection),
				5: capMap(nodecap.DisableCaptivePortalDetection),
			},
		},
		{
			name: "merging two grants on overlapping targets unions attrs",
			extra: `"nodeAttrs": [
				{"target": ["*"],          "attr": ["drive:access"]},
				{"target": ["tag:server"], "attr": ["drive:share"]}
			]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(nodecap.TaildriveAccess),
				2: capMap(nodecap.TaildriveAccess),
				3: {
					nodecap.TaildriveAccess: nil,
					nodecap.TaildriveShare:  nil,
				},
				4: capMap(nodecap.TaildriveAccess),
				5: capMap(nodecap.TaildriveAccess),
			},
		},
		{
			name:  "empty entry compiles to nothing",
			extra: `"nodeAttrs": [{"target": ["*"]}]`,
			want:  nil,
		},
		{
			name:  "top-level randomizeClientPort stamps every node",
			extra: `"randomizeClientPort": true`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(nodecap.RandomizeClientPort),
				2: capMap(nodecap.RandomizeClientPort),
				3: capMap(nodecap.RandomizeClientPort),
				4: capMap(nodecap.RandomizeClientPort),
				5: capMap(nodecap.RandomizeClientPort),
			},
		},
		{
			name: "global randomize plus per-tag entry merges",
			extra: `"randomizeClientPort": true,
				"nodeAttrs": [{"target": ["tag:server"], "attr": ["disable-captive-portal-detection"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(nodecap.RandomizeClientPort),
				2: capMap(nodecap.RandomizeClientPort),
				3: {
					nodecap.RandomizeClientPort:           nil,
					nodecap.DisableCaptivePortalDetection: nil,
				},
				4: capMap(nodecap.RandomizeClientPort),
				5: capMap(nodecap.RandomizeClientPort),
			},
		},
	}

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		` + tt.extra + `
	}`

			pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
			require.NoErrorf(t, err, "policy must parse and validate:\n%s", policy)

			got, err := pm.pol.compileNodeAttrs(users, pm.nodes)
			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("compileNodeAttrs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeAttrsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		extra   string
		wantErr error
	}{
		{
			name:    "autogroup:self target rejected",
			extra:   `"nodeAttrs": [{"target": ["autogroup:self"], "attr": ["randomize-client-port"]}]`,
			wantErr: ErrNodeAttrsAutogroupNotAllowed,
		},
		{
			name:    "autogroup:admin target rejected with user-role hint",
			extra:   `"nodeAttrs": [{"target": ["autogroup:admin"], "attr": ["randomize-client-port"]}]`,
			wantErr: ErrNodeAttrsAutogroupNotAllowed,
		},
		{
			name:    "autogroup:owner target rejected with user-role hint",
			extra:   `"nodeAttrs": [{"target": ["autogroup:owner"], "attr": ["randomize-client-port"]}]`,
			wantErr: ErrNodeAttrsAutogroupNotAllowed,
		},
		{
			name:    "funnel attr rejected as unsupported",
			extra:   `"nodeAttrs": [{"target": ["*"], "attr": ["funnel"]}]`,
			wantErr: ErrNodeAttrUnsupported,
		},
		{
			name:    "ipPool target must be one exact user",
			extra:   `"nodeAttrs": [{"target": ["autogroup:member"], "ipPool": ["100.81.0.0/16"]}]`,
			wantErr: ErrNodeAttrsIPPoolTarget,
		},
		{
			name:    "ipPool overlapping reserved range rejected at validate",
			extra:   `"nodeAttrs": [{"target": ["alice@example.com"], "ipPool": ["100.100.100.0/24"]}]`,
			wantErr: ErrNodeAttrsIPPoolReserved,
		},
	}

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		` + tt.extra + `
	}`

			_, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestNodeAttrsIPPoolValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prefix  string
		wantErr error
	}{
		{name: "in cgnat", prefix: "100.81.0.0/16"},
		{name: "private class a", prefix: "10.0.0.0/8"},
		{name: "private class b", prefix: "172.16.0.0/12"},
		{name: "private class c", prefix: "192.168.0.0/16"},
		{name: "ipv6 ula", prefix: "fd42:1234::/64"},
		{name: "less specific than cgnat", prefix: "100.0.0.0/8", wantErr: ErrNodeAttrsIPPoolOutOfRange},
		{name: "public ipv4", prefix: "8.8.8.0/24", wantErr: ErrNodeAttrsIPPoolOutOfRange},
		{name: "less specific than ula", prefix: "fc00::/6", wantErr: ErrNodeAttrsIPPoolOutOfRange},
		{name: "link local ipv6", prefix: "fe80::/64", wantErr: ErrNodeAttrsIPPoolOutOfRange},
		{name: "whole cgnat overlaps reserved", prefix: "100.64.0.0/10", wantErr: ErrNodeAttrsIPPoolReserved},
		{name: "overlaps quad100", prefix: "100.100.100.0/24", wantErr: ErrNodeAttrsIPPoolReserved},
		{name: "overlaps ipn", prefix: "100.115.92.0/24", wantErr: ErrNodeAttrsIPPoolReserved},
		{name: "ipv4 slash 31 cannot allocate", prefix: "10.20.30.0/31", wantErr: ErrNodeAttrsIPPoolTooSmall},
		{name: "ipv4 single host cannot allocate", prefix: "10.20.30.1/32", wantErr: ErrNodeAttrsIPPoolTooSmall},
		{name: "ipv6 slash 127 cannot allocate", prefix: "fd42:1234::/127", wantErr: ErrNodeAttrsIPPoolTooSmall},
		{name: "ipv6 single host cannot allocate", prefix: "fd42:1234::1/128", wantErr: ErrNodeAttrsIPPoolTooSmall},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateNodeAttrIPPool(netip.MustParsePrefix(tt.prefix))
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestNodeAttrsIPPoolUserValidation(t *testing.T) {
	t.Parallel()

	baseUsers := append(nodeAttrsTestUsers(), types.User{ID: 3, Name: "carol", Email: "carol@example.net"})
	baseNodes := nodeAttrsTestNodes(baseUsers)

	tests := []struct {
		name    string
		policy  string
		wantErr error
	}{
		{
			name:   "exact user pool accepted",
			policy: `{"nodeAttrs":[{"target":["carol@example.net"],"ipPool":["10.20.30.0/24","fd42:1234::/64"]}]}`,
		},
		{
			name:    "wildcard target rejected",
			policy:  `{"nodeAttrs":[{"target":["user:*@example.net"],"ipPool":["10.20.30.0/24"]}]}`,
			wantErr: ErrNodeAttrsIPPoolTarget,
		},
		{
			name: "duplicate user rejected",
			policy: `{"nodeAttrs":[
				{"target":["carol@example.net"],"ipPool":["10.20.30.0/24"]},
				{"target":["carol@example.net"],"ipPool":["10.20.31.0/24"]}
			]}`,
			wantErr: ErrNodeAttrsIPPoolDuplicate,
		},
		{
			name: "overlapping users rejected",
			policy: `{"nodeAttrs":[
				{"target":["carol@example.net"],"ipPool":["10.20.0.0/16"]},
				{"target":["alice@example.com"],"ipPool":["10.20.30.0/24"]}
			]}`,
			wantErr: ErrNodeAttrsIPPoolOverlap,
		},
		{
			name:    "existing owned address outside pool rejected",
			policy:  `{"nodeAttrs":[{"target":["alice@example.com"],"ipPool":["10.20.30.0/24"]}]}`,
			wantErr: ErrNodeAttrsIPPoolNodeConflict,
		},
		{
			name:    "other user's node inside pool rejected",
			policy:  `{"nodeAttrs":[{"target":["carol@example.net"],"ipPool":["100.64.0.0/24"]}]}`,
			wantErr: ErrNodeAttrsIPPoolNodeConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pm, err := NewPolicyManager([]byte(tt.policy), baseUsers, baseNodes.ViewSlice())
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			if tt.name == "exact user pool accepted" {
				assert.Equal(t, []netip.Prefix{
					netip.MustParsePrefix("10.20.30.0/24"),
					netip.MustParsePrefix("fd42:1234::/64"),
				}, pm.IPPoolForUser(3))
				for _, node := range baseNodes {
					assert.Contains(t, pm.NodeCapMap(node.ID), nodecap.OneCGNATDisable)
				}
			}
		})
	}
}

func TestNodeAttrsIPPoolExistingAddressesInUsablePool(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := types.Nodes{{
		ID:        1,
		GivenName: "alice-custom",
		User:      &users[0],
		UserID:    &users[0].ID,
		IPv4:      ptrAddr("10.20.30.1"),
		IPv6:      ptrAddr("fd42:1234::1"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}}

	pm, err := NewPolicyManager([]byte(`{"nodeAttrs":[{"target":["alice@example.com"],"ipPool":["10.20.30.0/30","fd42:1234::/126"]}]}`), users, nodes.ViewSlice())
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.20.30.0/30"),
		netip.MustParsePrefix("fd42:1234::/126"),
	}, pm.IPPoolForUser(types.UserID(users[0].ID)))
	assert.Contains(t, pm.NodeCapMap(nodes[0].ID), nodecap.OneCGNATDisable)
}

func TestNodeAttrsIPv6OnlyPoolKeepsAutomaticCGNATRouting(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := types.Nodes{{
		ID:        1,
		GivenName: "alice-custom-v6",
		User:      &users[0],
		UserID:    &users[0].ID,
		IPv6:      ptrAddr("fd42:1234::1"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}}

	pm, err := NewPolicyManager([]byte(`{"nodeAttrs":[{"target":["alice@example.com"],"ipPool":["fd42:1234::/126"]}]}`), users, nodes.ViewSlice())
	require.NoError(t, err)
	assert.NotContains(t, pm.NodeCapMap(nodes[0].ID), nodecap.OneCGNATDisable)
}

func TestWildcardACLIncludesCustomPoolNodeAddresses(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := types.Nodes{
		{
			ID:        1,
			GivenName: "alice-custom",
			User:      &users[0],
			UserID:    &users[0].ID,
			IPv4:      ptrAddr("10.42.0.1"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        2,
			GivenName: "bob-custom",
			User:      &users[1],
			UserID:    &users[1].ID,
			IPv4:      ptrAddr("10.43.0.1"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
	}

	pm, err := NewPolicyManager([]byte(`{
		"nodeAttrs": [
			{"target": ["alice@example.com"], "ipPool": ["10.42.0.0/24"]},
			{"target": ["bob@example.org"], "ipPool": ["10.43.0.0/24"]}
		],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	matchers, err := pm.MatchersForNode(nodes[0].View())
	require.NoError(t, err)
	assert.True(t, nodes[0].View().CanAccess(matchers, nodes[1].View()))
}

func TestWildcardACLDoesNotExpandUnpooledNonstandardAddresses(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := types.Nodes{
		{
			ID:        1,
			GivenName: "alice-custom",
			User:      &users[0],
			UserID:    &users[0].ID,
			IPv4:      ptrAddr("10.42.0.1"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        2,
			GivenName: "legacy",
			User:      &users[1],
			UserID:    &users[1].ID,
			IPv4:      ptrAddr("200.200.200.200"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
	}
	policy := &Policy{NodeAttrs: []NodeAttrGrant{{
		Targets: Aliases{up("alice@example.com")},
		IPPool:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/24")},
	}}}

	resolved, err := Asterix(0).Resolve(policy, users, nodes.ViewSlice())
	require.NoError(t, err)
	assert.True(t, resolved.Contains(netip.MustParseAddr("10.42.0.1")))
	assert.False(t, resolved.Contains(netip.MustParseAddr("200.200.200.200")))
}

func TestNodesWithChangedCapMap(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	policyA := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{
			"target": ["tag:server"],
			"attr":   ["randomize-client-port"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(policyA), users, nodes.ViewSlice())
	require.NoError(t, err)

	initial := pm.NodesWithChangedCapMap()
	slices.Sort(initial)
	assert.Equal(t, []types.NodeID{3}, initial,
		"first build reports every node with a non-empty CapMap")

	// Swap targets: server loses the attr, client and prod gain it.
	policyB := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{
			"target": ["tag:client", "tag:prod"],
			"attr":   ["randomize-client-port"]
		}]
	}`

	changed, err := pm.SetPolicy([]byte(policyB))
	require.NoError(t, err)
	require.True(t, changed)

	delta := pm.NodesWithChangedCapMap()
	slices.Sort(delta)
	assert.Equal(t, []types.NodeID{3, 4, 5}, delta,
		"server lost the cap, client and prod gained it -- diff is the symmetric difference")

	assert.Empty(t, pm.NodesWithChangedCapMap(),
		"NodesWithChangedCapMap drains its buffer on read")

	// Reload the same bytes. updateLocked still runs, but no node's
	// CapMap hash should change.
	_, err = pm.SetPolicy([]byte(policyB))
	require.NoError(t, err)

	assert.Empty(t, pm.NodesWithChangedCapMap(),
		"reloading the same policy must not produce CapMap diffs")
}

// TestMalformedNextDNSAttrWarnsOnceAtLoad pins that a nextdns: attr whose
// profile the resolver skips still loads and stays in the CapMap, as on
// Tailscale SaaS, and is logged once per policy load. Not parallel: it swaps
// the global logger and level.
func TestMalformedNextDNSAttrWarnsOnceAtLoad(t *testing.T) {
	var buf bytes.Buffer

	prev, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)

	zerolog.SetGlobalLevel(zerolog.WarnLevel)

	t.Cleanup(func() {
		log.Logger = prev

		zerolog.SetGlobalLevel(prevLevel)
	})

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	pol := []byte(`{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{"target": ["*"], "attr": ["nextdns:a/b?c", "nextdns:abc123"]}]
	}`)

	pm, err := NewPolicyManager(pol, users, nodes.ViewSlice())
	require.NoError(t, err)

	// The write path reloads the bytes it just set.
	_, err = pm.SetPolicy(pol)
	require.NoError(t, err)

	assert.Contains(t, pm.NodeCapMap(1), nodecap.Cap("nextdns:a/b?c"))
	assert.Equal(t, 1, strings.Count(buf.String(), "nextdns:a/b?c"), buf.String())
	assert.NotContains(t, buf.String(), "nextdns:abc123")
}
