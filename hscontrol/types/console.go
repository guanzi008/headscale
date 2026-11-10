package types

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/prometheus/common/model"
	"github.com/spf13/viper"
)

// ConsoleTailnetConfig loads a network's editable configuration without changing
// Viper's process-wide configuration or sharing mutable DNS state with another
// network. Listener and identity-provider settings remain platform-managed.
func ConsoleTailnetConfig(base *Config, root, path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read personal network configuration: %w", err)
	}
	cfg := *base
	cfg.ConsoleTailnetID = filepath.Base(root)
	cfg.Database.Type = "sqlite3"
	cfg.Database.Sqlite.Path = filepath.Join(root, "headscale", "db.sqlite")
	cfg.Database.Sqlite.WriteAheadLog = true
	cfg.UnixSocket = filepath.Join(root, "headscale", "headscale.sock")
	cfg.Policy = PolicyConfig{Mode: PolicyModeDB}
	cfg.DNSConfig = DNSConfig{}
	if err := v.UnmarshalKey("dns", &cfg.DNSConfig); err != nil {
		return nil, fmt.Errorf("read personal network DNS: %w", err)
	}
	if cfg.DNSConfig.BaseDomain == "" {
		return nil, fmt.Errorf("personal network DNS base domain is required")
	}
	cfg.BaseDomain = cfg.DNSConfig.BaseDomain
	cfg.DNSConfig.ExtraRecordsPath = filepath.Join(root, "headscale", "extra-records.json")
	cfg.DNSConfig.Certificates = CertificatesConfig{}
	cfg.DNSChallenge = DNSChallengeConfig{}
	cfg.TailcfgDNSConfig = dnsToTailcfgDNS(cfg.DNSConfig)
	cfg.ipPoolDNSRoutes = nil
	if v.IsSet("node.expiry") {
		expiry, err := model.ParseDuration(v.GetString("node.expiry"))
		if err != nil {
			return nil, fmt.Errorf("invalid personal network node expiry: %w", err)
		}
		cfg.Node.Expiry = time.Duration(expiry)
	}
	if v.IsSet("taildrop.enabled") {
		cfg.Taildrop.Enabled = v.GetBool("taildrop.enabled")
	}
	if v.IsSet("auto_update.enabled") {
		cfg.AutoUpdate.Enabled = v.GetBool("auto_update.enabled")
	}
	cfg.OIDC.AllowedDomains = v.GetStringSlice("oidc.allowed_domains")
	cfg.OIDC.AllowedUsers = v.GetStringSlice("oidc.allowed_users")
	cfg.OIDC.AllowedGroups = v.GetStringSlice("oidc.allowed_groups")
	return &cfg, nil
}
