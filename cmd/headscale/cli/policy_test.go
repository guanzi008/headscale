package cli

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func TestOfflinePolicyChecksNewPoolsAgainstExistingNodes(t *testing.T) {
	d, err := db.NewHeadscaleDatabase(&types.Config{Database: types.DatabaseConfig{
		Type: types.DatabaseSqlite, Sqlite: types.SqliteConfig{Path: t.TempDir() + "/headscale.db"},
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	d.CreateUserForTest("alice")
	bob := d.CreateUserForTest("bob")
	node := d.CreateRegisteredNodeForTest(bob, "bob-existing")
	require.NoError(t, d.DB.Model(&types.Node{}).Where("id = ?", node.ID).Update("ipv4", "10.42.0.1").Error)

	err = validateOfflinePolicy(d, []byte(`{"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24"]}]}`))
	require.ErrorContains(t, err, "conflicts with an existing node address")

	// Stored pools can legitimately retain devices that have since become
	// tagged. An unrelated offline edit must preserve that allocation.
	node.IPv4 = new(netip.MustParseAddr("10.42.0.1"))
	node.Tags = types.Strings{"tag:server"}
	node.UserID = nil
	require.NoError(t, d.DB.Model(&types.Node{}).Where("id = ?", node.ID).
		Select("ipv4", "tags", "user_id").Updates(node).Error)
	const stored = `{"tagOwners":{"tag:server":["alice@"]},"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24"]}]}`
	_, err = d.SetPolicy(stored)
	require.NoError(t, err)
	err = validateOfflinePolicy(d, []byte(`{"tagOwners":{"tag:server":["alice@"]},"nodeAttrs":[{"target":["alice@"],"ipPool":["10.42.0.0/24"]}],"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)
}

func TestOfflinePolicyCanRepairInvalidStoredPolicy(t *testing.T) {
	d, err := db.NewHeadscaleDatabase(&types.Config{Database: types.DatabaseConfig{
		Type: types.DatabaseSqlite, Sqlite: types.SqliteConfig{Path: t.TempDir() + "/headscale.db"},
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	_, err = d.SetPolicy(`{"nodeAttrs":`)
	require.NoError(t, err)
	require.NoError(t, validateOfflinePolicy(d, []byte(`{}`)))
}
