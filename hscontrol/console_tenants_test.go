package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestConsoleTailnetsKeepStateAndCredentialsSeparate(t *testing.T) {
	root := createTestApp(t, func(cfg *types.Config) {
		v4 := netip.MustParsePrefix("100.64.0.0/10")
		v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
		cfg.PrefixV4, cfg.PrefixV6 = &v4, &v6
		cfg.IPAllocation = types.IPAllocationStrategySequential
	})
	manager, err := newConsoleTailnets(context.Background(), root, t.TempDir(), "")
	require.NoError(t, err)
	t.Cleanup(manager.close)
	root.console = manager
	alice, err := manager.ensure(consoleOwner{ID: "usr_aaaaaaaaaaaaaaaaaaaaaaaa", Email: "alice@example.com", Name: "Alice"})
	require.NoError(t, err)
	bob, err := manager.ensure(consoleOwner{ID: "usr_bbbbbbbbbbbbbbbbbbbbbbbb", Email: "bob@example.com", Name: "Bob"})
	require.NoError(t, err)
	require.NotEqual(t, alice.h.cfg.Database.Sqlite.Path, bob.h.cfg.Database.Sqlite.Path)
	require.NotEqual(t, alice.h.cfg.BaseDomain, bob.h.cfg.BaseDomain)
	aliceUsers, err := alice.h.state.ListAllUsers()
	require.NoError(t, err)
	bobUsers, err := bob.h.state.ListAllUsers()
	require.NoError(t, err)
	require.Len(t, aliceUsers, 1)
	require.Len(t, bobUsers, 1)
	require.NotEqual(t, aliceUsers[0].ID, bobUsers[0].ID, "client account profiles share one control URL and need distinct public user IDs")
	require.Equal(t, "alice@example.com", aliceUsers[0].Email)
	require.Equal(t, "bob@example.com", bobUsers[0].Email)
	_, _, err = alice.h.state.CreateUser(types.User{Name: "alice-private"})
	require.NoError(t, err)
	bobUsers, err = bob.h.state.ListAllUsers()
	require.NoError(t, err)
	require.Len(t, bobUsers, 1)
	valid, _ := bob.h.state.ValidateAPIKey(alice.apiKey)
	require.False(t, valid)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
	request.Header.Set("Authorization", "Bearer "+alice.apiKey)
	response := httptest.NewRecorder()
	root.HTTPHandler().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "alice-private")
	require.NotContains(t, response.Body.String(), "bob@example.com")
	_, _, err = alice.h.state.UpdatePolicy([]byte(`{"acls":[]}`))
	require.NoError(t, err)
	bobPolicy, err := bob.h.state.GetPolicy()
	require.NoError(t, err)
	require.Contains(t, bobPolicy.Data, "accept")
	pingID, reply := bob.h.state.RegisterPing(types.NodeID(1))
	response = httptest.NewRecorder()
	root.HTTPHandler().ServeHTTP(response, httptest.NewRequest(http.MethodHead, "/machine/ping-response?id="+pingID, nil))
	require.Equal(t, http.StatusOK, response.Code)
	<-reply
	aliceUserID := aliceUsers[0].ID
	require.NoError(t, manager.reload(alice.owner.ID))
	alice, err = manager.ensure(alice.owner)
	require.NoError(t, err)
	reloadedOwner, err := alice.h.state.GetUserByID(types.UserID(aliceUserID))
	require.NoError(t, err)
	require.Equal(t, aliceUserID, reloadedOwner.ID)
	currentBob, err := manager.ensure(bob.owner)
	require.NoError(t, err)
	require.Same(t, bob, currentBob, "a network configuration reload must not restart another network")
	bobUserID := types.UserID(bobUsers[0].ID)
	authKey, err := bob.h.state.CreatePreAuthKey(&bobUserID, true, false, nil, nil)
	require.NoError(t, err)
	nodeKey, nodeMachineKey := key.NewNode().Public(), key.NewMachine().Public()
	_, err = bob.h.handleRegister(t.Context(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey,
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: authKey.Key},
		Hostinfo: &tailcfg.Hostinfo{Hostname: "bob-private", OS: "linux"},
	}, nodeMachineKey)
	require.NoError(t, err)
	node, found := bob.h.state.GetNodeByNodeKey(nodeKey)
	require.True(t, found)
	for _, machineKey := range []key.MachinePublic{nodeMachineKey, key.NewMachine().Public()} {
		session := noiseServer{headscale: root, machineKey: machineKey, consoleScope: &consoleNoiseScope{}}
		router := chi.NewRouter()
		router.Get("/machine/ssh/action/{src_node_id}/to/{dst_node_id}", session.consoleHandler(func(selected *noiseServer, w http.ResponseWriter, _ *http.Request) {
			require.Same(t, bob.h, selected.headscale)
			w.WriteHeader(http.StatusNoContent)
		}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/machine/ssh/action/1/to/"+strconv.FormatUint(node.ID().Uint64(), 10), nil))
		if machineKey == nodeMachineKey {
			require.Equal(t, http.StatusNoContent, response.Code)
		} else {
			require.Equal(t, http.StatusNotFound, response.Code)
		}
	}
	require.NoError(t, manager.remove(alice.owner.ID))
	_, err = manager.ensure(alice.owner)
	require.Error(t, err)
	response = httptest.NewRecorder()
	root.HTTPHandler().ServeHTTP(response, request)
	require.NotEqual(t, http.StatusOK, response.Code)
	require.False(t, strings.Contains(response.Body.String(), "alice-private"))
	manager.close()
	restored, err := newConsoleTailnets(t.Context(), root, manager.dir, "")
	require.NoError(t, err)
	t.Cleanup(restored.close)
	root.console = restored
	_, err = restored.ensure(alice.owner)
	require.ErrorIs(t, err, errConsoleNetworkDeleted, "deleted networks must stay deleted after restart")
	restoredBob, err := restored.ensure(bob.owner)
	require.NoError(t, err)
	require.Equal(t, bob.apiKey, restoredBob.apiKey)
	restoredNode, found := restoredBob.h.state.GetNodeByNodeKey(nodeKey)
	require.True(t, found)
	require.Equal(t, node.ID(), restoredNode.ID())
	require.Equal(t, node.UserID(), restoredNode.UserID())
}
