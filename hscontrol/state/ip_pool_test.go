package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
)

func TestUserIPPoolsAreReservedAcrossPolicyUpdates(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("alice")
	require.NoError(t, s.UpdatePolicyManagerUsersForTest())

	next4 := func() netip.Addr {
		t.Helper()

		ipv4, _, err := s.ipAlloc.Next()
		require.NoError(t, err)
		require.NotNil(t, ipv4)

		return *ipv4
	}

	policyWithPool := func(prefix string) []byte {
		return []byte(`{"nodeAttrs":[{"target":["alice@"],"ipPool":["` + prefix + `"]}]}`)
	}

	changed, err := s.SetPolicy(policyWithPool("100.64.0.4/30"))
	require.NoError(t, err)
	require.True(t, changed)
	for _, want := range []string{"100.64.0.1", "100.64.0.2", "100.64.0.3", "100.64.0.8"} {
		assert.Equal(t, netip.MustParseAddr(want), next4())
	}

	changed, err = s.SetPolicy(policyWithPool("100.64.0.8/30"))
	require.NoError(t, err)
	require.True(t, changed)
	assert.Equal(t, netip.MustParseAddr("100.64.0.12"), next4())

	_, _, err = s.UpdatePolicy(policyWithPool("100.64.0.16/30"))
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("100.64.0.13"), next4())

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.16/30")}, s.polMan.IPPoolForUser(types.UserID(user.ID)))
}

func TestUserIPPoolsUpdateMagicDNSReverseRoutes(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{Proxied: true}

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	s.CreateUserForTest("alice")
	require.NoError(t, s.UpdatePolicyManagerUsersForTest())

	_, err = s.SetPolicy([]byte(`{"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/16"]}]}`))
	require.NoError(t, err)
	require.Contains(t, cfg.TailcfgDNSConfig.Routes, "42.10.in-addr.arpa")

	_, err = s.SetPolicy([]byte(`{}`))
	require.NoError(t, err)
	require.NotContains(t, cfg.TailcfgDNSConfig.Routes, "42.10.in-addr.arpa")
}

func TestNewNodesUseDeviceUserPools(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	alice := database.CreateUserForTest("alice")
	database.CreateUserForTest("bob")
	_, err = database.SetPolicy(`{
		"nodeAttrs": [{
			"target": ["alice@"],
			"ipPool": ["100.64.0.0/29", "fd42:1234::/64"]
		}]
	}`)
	require.NoError(t, err)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	register := func(user *types.User, hostname string) types.NodeView {
		t.Helper()

		authKey, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
		require.NoError(t, err)

		node, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: authKey.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
		}, key.NewMachine().Public())
		require.NoError(t, err)

		return node
	}

	aliceNode := register(alice, "alice-node")
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd42:1234::1")}, aliceNode.IPs())
	assert.Contains(t, s.polMan.NodeCapMap(aliceNode.ID()), nodecap.OneCGNATDisable)

	bob, err := s.GetUserByName("bob")
	require.NoError(t, err)
	bobNode := register(bob, "bob-node")
	assert.Contains(t, bobNode.IPs(), netip.MustParseAddr("100.64.0.8"))
	assert.Contains(t, s.polMan.NodeCapMap(bobNode.ID()), nodecap.OneCGNATDisable)
}

func TestBackfillUsesDeviceUserPools(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	alice := database.CreateUserForTest("alice")
	node := database.CreateRegisteredNodeForTest(alice, "backfill-alice")
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", node.ID).Update("ipv4", nil).Error)
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", node.ID).Update("host_info", "{}").Error)
	_, err = database.SetPolicy(`{"nodeAttrs":[{"target":["alice@"],"ipPool":["10.20.30.0/30"]}]}`)
	require.NoError(t, err)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	backfilled, _, err := s.BackfillNodeIPs()
	require.NoError(t, err)
	require.NotEmpty(t, backfilled)

	fresh, _ := s.GetNodeByID(node.ID)
	assert.Contains(t, fresh.IPs(), netip.MustParseAddr("10.20.30.1"))
}

func TestBackfillDoesNotUseUserPoolsForTaggedNodes(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	alice := database.CreateUserForTest("alice")
	node := database.CreateRegisteredNodeForTest(alice, "backfill-tagged-alice")
	node.IPv4 = nil
	node.IPv6 = nil
	node.Tags = types.Strings{"tag:server"}
	node.Hostinfo = &tailcfg.Hostinfo{}
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", node.ID).
		Select("ipv4", "ipv6", "tags", "host_info").Updates(node).Error)
	_, err = database.SetPolicy(`{
		"tagOwners": {"tag:server": ["alice@"]},
		"nodeAttrs": [{"target": ["alice@"], "ipPool": ["10.20.30.0/30"]}]
	}`)
	require.NoError(t, err)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	backfilled, _, err := s.BackfillNodeIPs()
	require.NoError(t, err)
	require.NotEmpty(t, backfilled)

	fresh, _ := s.GetNodeByID(node.ID)
	require.True(t, fresh.IsTagged())
	require.NotEmpty(t, fresh.IPs())
	for _, addr := range fresh.IPs() {
		assert.False(t, netip.MustParsePrefix("10.20.30.0/30").Contains(addr), "tagged node received a user-pool address %s", addr)
	}
}
