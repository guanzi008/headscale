package state

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
)

func TestUserIPPoolsControlServedHostRoutes(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	alice := s.CreateUserForTest("alice")
	bob := s.CreateUserForTest("bob")
	require.NoError(t, s.UpdatePolicyManagerUsersForTest())

	setPools := func(pools []string) {
		t.Helper()
		encoded, err := json.Marshal(pools)
		require.NoError(t, err)
		_, _, err = s.UpdatePolicy([]byte(`{
			"tagOwners":{"tag:router":["alice@"]},
			"nodeAttrs":[{"target":["alice@"],"ipPool":` + string(encoded) + `},
			{"target":["bob@"],"ipPool":["10.43.0.0/24","fd43::/64"]}],
			"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]
		}`))
		require.NoError(t, err)
	}
	dualPools := []string{"10.42.0.0/24", "fd42:1::/64"}
	setPools(dualPools)
	router := registerIPPoolTestNode(t, s, alice, "subnet-router")
	client := registerIPPoolTestNode(t, s, alice, "android")
	other := registerIPPoolTestNode(t, s, bob, "other-user")

	outside4 := netip.MustParsePrefix("100.84.4.113/32")
	mapped4 := netip.MustParsePrefix("::ffff:100.84.4.114/128")
	outside6 := netip.MustParsePrefix("fd7a:115c:a1e0::123/128")
	pool4 := netip.MustParsePrefix("10.42.0.123/32")
	pool6 := netip.MustParsePrefix("fd42:1::123/128")
	subnet := netip.MustParsePrefix("10.42.0.0/24")
	via := netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a09:5/128")
	routes := []netip.Prefix{outside4, mapped4, outside6, pool4, pool6, subnet, via}
	// Already assigned addresses must remain protected even after their
	// owner's pool changes, and even if they belong to another user.
	for _, node := range []types.NodeView{router, client, other} {
		for _, addr := range node.IPs() {
			routes = append(routes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	_, err = s.UpdateNodeFromMapRequest(router.ID(), tailcfg.MapRequest{
		NodeKey:  router.NodeKey(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "subnet-router", RoutableIPs: routes},
	})
	require.NoError(t, err)
	_, _, err = s.SetApprovedRoutes(router.ID(), routes)
	require.NoError(t, err)
	_, epoch := s.Connect(router.ID())
	require.NotZero(t, epoch)

	check := func(want []netip.Prefix) {
		t.Helper()
		freshRouter, ok := s.GetNodeByID(router.ID())
		require.True(t, ok)
		freshClient, ok := s.GetNodeByID(client.ID())
		require.True(t, ok)
		matchers, err := s.MatchersForNode(freshClient)
		require.NoError(t, err)
		assert.ElementsMatch(t, want, s.RoutesForPeer(freshClient, freshRouter, matchers), "routes delivered to the client")
		assert.ElementsMatch(t, want, s.GetNodePrimaryRoutes(router.ID()), "routes reported as serving by the API")
		assert.ElementsMatch(t, routes, freshRouter.ApprovedRoutes().AsSlice(), "approval must survive pool changes")
		assert.Equal(t, router.IPs(), freshRouter.IPs(), "existing device addresses must stay stable")
	}

	for _, tt := range []struct {
		name  string
		pools []string
		want  []netip.Prefix
	}{
		{"both_families", dualPools, []netip.Prefix{outside4, mapped4, outside6, subnet, via}},
		{"ipv4_only", dualPools[:1], []netip.Prefix{outside4, mapped4, pool6, subnet, via}},
		{"ipv6_only", dualPools[1:], []netip.Prefix{outside6, pool4, subnet, via}},
		{"cleared", []string{}, []netip.Prefix{pool4, pool6, subnet, via}},
		{"restored", dualPools, []netip.Prefix{outside4, mapped4, outside6, subnet, via}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setPools(tt.pools)
			check(tt.want)
		})
	}

	require.NoError(t, s.Close())
	s, err = NewState(cfg)
	require.NoError(t, err)
	s.Connect(router.ID())
	check([]netip.Prefix{outside4, mapped4, outside6, subnet, via})

	// Tags own a tagged router; its creator's pool must not be used.
	_, _, err = s.SetNodeTags(router.ID(), []string{"tag:router"})
	require.NoError(t, err)
	check([]netip.Prefix{pool4, pool6, subnet, via})
}

func TestDeleteIPPoolOwnerKeepsPolicyAndRestartWorking(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if s != nil {
			_ = s.Close()
		}
	})
	alice := s.CreateUserForTest("alice")
	require.NoError(t, s.UpdatePolicyManagerUsersForTest())
	_, _, err = s.UpdatePolicy([]byte(`{"nodeAttrs":[{"target":["alice@"],"ipPool":["100.64.0.0/29"]}]}`))
	require.NoError(t, err)
	_, err = s.DeleteUser(types.UserID(alice.ID))
	require.NoError(t, err)
	_, err = s.GetUserByName("alice")
	require.ErrorIs(t, err, db.ErrUserNotFound)
	require.NoError(t, s.Close())
	s = nil
	s, err = NewState(cfg)
	require.NoError(t, err)
	// A dangling user reference must stay reserved, so recreating the user
	// cannot find that another user's new device took its pool in between.
	ip, _, err := s.ipAlloc.Next()
	require.NoError(t, err)
	require.NotNil(t, ip)
	assert.Equal(t, netip.MustParseAddr("100.64.0.8"), *ip)
}

func TestPoolNodeTaggingPreservesAddressesAndRestart(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if s != nil {
			_ = s.Close()
		}
	})
	alice := s.CreateUserForTest("alice")
	require.NoError(t, s.UpdatePolicyManagerUsersForTest())
	_, _, err = s.UpdatePolicy([]byte(`{"tagOwners":{"tag:server":["alice@"]},"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24"]}]}`))
	require.NoError(t, err)
	node := registerIPPoolTestNode(t, s, alice, "alice-tagged")
	ips := node.IPs()
	tagged, _, err := s.SetNodeTags(node.ID(), []string{"tag:server"})
	require.NoError(t, err)
	require.True(t, tagged.IsTagged())
	assert.Equal(t, ips, tagged.IPs())
	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	// An unrelated policy edit must not reinterpret an already assigned IP
	// as a new allocation to the node's former owner.
	_, _, err = s.UpdatePolicy([]byte(`{"tagOwners":{"tag:server":["alice@"]},"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24"]}],"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
	require.NoError(t, s.Close())
	s = nil
	s, err = NewState(cfg)
	require.NoError(t, err)
	fresh, ok := s.GetNodeByID(node.ID())
	require.True(t, ok)
	assert.True(t, fresh.IsTagged())
	assert.Equal(t, ips, fresh.IPs())
}

func TestClearingPoolsKeepsExistingPrivateNodesReachable(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{Proxied: true}
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	alice := s.CreateUserForTest("alice")
	bob := s.CreateUserForTest("bob")
	require.NoError(t, s.UpdatePolicyManagerUsersForTest())
	_, _, err = s.UpdatePolicy([]byte(`{"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24","fd42::/64"]},{"target":["bob@"],"ipPool":["10.43.0.0/24","fd43::/64"]}],"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
	a := registerIPPoolTestNode(t, s, alice, "alice-private")
	b := registerIPPoolTestNode(t, s, bob, "bob-private")
	_, _, err = s.UpdatePolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
	matchers, err := s.MatchersForNode(a)
	require.NoError(t, err)
	assert.True(t, a.CanAccess(matchers, b), "clearing a pool must not revoke wildcard access")
	assert.Contains(t, s.NodeCapMap(a.ID()), nodecap.OneCGNATDisable)
	for _, addr := range a.IPs() {
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		var zones []string
		if addr.Is4() {
			for _, zone := range util.GenerateIPv4DNSRootDomain(prefix) {
				zones = append(zones, zone.WithoutTrailingDot())
			}
		} else {
			for _, zone := range util.GenerateIPv6DNSRootDomain(prefix) {
				zones = append(zones, zone.WithoutTrailingDot())
			}
		}
		for _, zone := range zones {
			assert.Contains(t, cfg.CloneTailcfgDNSConfig().Routes, zone)
		}
	}
	newNode := registerIPPoolTestNode(t, s, alice, "alice-global")
	assert.Contains(t, newNode.IPs(), netip.MustParseAddr("100.64.0.1"))
}

func registerIPPoolTestNode(t *testing.T, s *State, user *types.User, hostname string) types.NodeView {
	t.Helper()
	authKey, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)
	node, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{AuthKey: authKey.Key}, NodeKey: key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}, key.NewMachine().Public())
	require.NoError(t, err)
	return node
}

func TestPolicyCanRepairInvalidStoredPolicy(t *testing.T) {
	s, err := NewState(persistTestConfig(t.TempDir() + "/headscale.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.db.SetPolicy(`{"nodeAttrs":`)
	require.NoError(t, err)
	_, _, err = s.UpdatePolicy([]byte(`{}`))
	require.NoError(t, err)
	stored, err := s.GetPolicy()
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, stored.Data)
}

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
