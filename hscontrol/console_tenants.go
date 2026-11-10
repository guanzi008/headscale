package hscontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
	"tailscale.com/types/key"
)

var consoleOwnerID = regexp.MustCompile(`^usr_[0-9a-f]{24}$`)
var errConsoleNetworkDeleted = errors.New("personal network has been deleted")

type consoleOwner struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted,omitempty"`
}

type consoleNetwork struct {
	owner      consoleOwner
	h          *Headscale
	apiKey     string
	configPath string
	handler    http.Handler
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	retired    bool
	requests   sync.WaitGroup
	background sync.WaitGroup
}

func (n *consoleNetwork) acquire() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.retired {
		return false
	}
	n.requests.Add(1)
	return true
}

func (n *consoleNetwork) serve(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	if !n.acquire() {
		http.Error(w, "Network unavailable", http.StatusForbidden)
		return
	}
	defer n.requests.Done()
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	defer cancel()
	handler.ServeHTTP(w, r.WithContext(ctx))
}

func (n *consoleNetwork) close() {
	n.mu.Lock()
	if n.retired {
		n.mu.Unlock()
		return
	}
	n.retired = true
	n.mu.Unlock()
	n.cancel()
	n.h.mapBatcher.Close()
	n.h.ephemeralGC.Close()
	n.requests.Wait()
	n.h.clientStreamsOpen.Wait()
	n.background.Wait()
	if n.h.extraRecordMan != nil {
		n.h.extraRecordMan.Close()
	}
	_ = n.h.state.Close()
}

type consoleTailnets struct {
	operations sync.Map
	idMu       sync.Mutex
	ids        map[string]map[uint64]string
	root       *Headscale
	dir        string
	template   string
	ctx        context.Context
	mu         sync.RWMutex
	items      map[string]*consoleNetwork
	bindings   *expirable.LRU[types.AuthID, *consoleNetwork]
	closed     bool
}

func newConsoleTailnets(ctx context.Context, root *Headscale, dir, template string) (*consoleTailnets, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &consoleTailnets{root: root, dir: dir, template: template, ctx: ctx, items: make(map[string]*consoleNetwork), bindings: expirable.NewLRU[types.AuthID, *consoleNetwork](10000, nil, 30*time.Minute)}
	if err := m.prepareIDs("legacy", root.state); err != nil {
		m.bindings.Close()
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		m.bindings.Close()
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !consoleOwnerID.MatchString(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name(), "owner.json"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			m.close()
			return nil, err
		}
		var owner consoleOwner
		if err := json.Unmarshal(data, &owner); err != nil {
			log.Error().Err(err).Str("tailnet", entry.Name()).Msg("personal network metadata unavailable")
			continue
		}
		if owner.ID != entry.Name() {
			m.close()
			return nil, fmt.Errorf("personal network owner does not match its directory")
		}
		if owner.Deleted {
			continue
		}
		if _, err := m.ensure(owner); err != nil {
			log.Error().Err(err).Str("tailnet", owner.ID).Msg("personal network unavailable; other networks remain active")
		}
	}
	return m, nil
}

func (m *consoleTailnets) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.mu.Unlock()
	m.bindings.Close()
	for _, item := range m.snapshot() {
		item.close()
	}
}

func (m *consoleTailnets) snapshot() []*consoleNetwork {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]*consoleNetwork, 0, len(m.items))
	for _, item := range m.items {
		items = append(items, item)
	}
	return items
}

func (m *consoleTailnets) operation(id string) *sync.Mutex {
	value, _ := m.operations.LoadOrStore(id, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (m *consoleTailnets) ensure(owner consoleOwner) (*consoleNetwork, error) {
	if !consoleOwnerID.MatchString(owner.ID) {
		return nil, fmt.Errorf("invalid personal network owner")
	}
	lock := m.operation(owner.ID)
	lock.Lock()
	defer lock.Unlock()
	return m.ensureLocked(owner)
}

func (m *consoleTailnets) ensureLocked(owner consoleOwner) (*consoleNetwork, error) {
	if !consoleOwnerID.MatchString(owner.ID) {
		return nil, fmt.Errorf("invalid personal network owner")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, fmt.Errorf("control server is stopping")
	}
	if item := m.items[owner.ID]; item != nil {
		return item, nil
	}
	root := filepath.Join(m.dir, owner.ID)
	ownerPath := filepath.Join(root, "owner.json")
	if data, err := os.ReadFile(ownerPath); err == nil {
		var previous consoleOwner
		if err := json.Unmarshal(data, &previous); err != nil {
			return nil, err
		}
		if previous.Deleted {
			return nil, errConsoleNetworkDeleted
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, dir := range []string{root, filepath.Join(root, "headscale"), filepath.Join(root, "generated")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	configPath := filepath.Join(root, "generated", "headscale.yaml")
	if err := m.initialConfig(root, configPath, owner.ID); err != nil {
		return nil, err
	}
	cfg, err := types.ConsoleTailnetConfig(m.root.cfg, root, configPath)
	if err != nil {
		return nil, err
	}
	// One public OIDC flow authenticates the account and selects its network.
	// Child control states reuse that provider without extra discovery clients.
	oidcConfig := cfg.OIDC
	cfg.OIDC = types.OIDCConfig{}
	child, err := NewHeadscale(cfg)
	if err != nil {
		return nil, err
	}
	cfg.OIDC = oidcConfig
	child.mapBatcher = mapper.NewBatcherAndMapper(cfg, child.state)
	child.mapBatcher.Start()
	ctx, cancel := context.WithCancel(m.ctx)
	item := &consoleNetwork{owner: owner, h: child, configPath: configPath, ctx: ctx, cancel: cancel}
	go child.ephemeralGC.Start()
	if err := m.prepareIDs(owner.ID, child.state); err != nil {
		item.close()
		return nil, err
	}
	fail := func(err error) (*consoleNetwork, error) { item.close(); return nil, err }
	if provider, ok := m.root.authProvider.(*AuthProviderOIDC); ok {
		copy := *provider
		copy.h, copy.cfg = child, &cfg.OIDC
		child.authProvider = &copy
	}
	claims := types.OIDCClaims{Sub: owner.ID, Iss: cfg.OIDC.Issuer, Email: owner.Email, Name: owner.Name, Username: owner.Email}
	user := types.User{}
	user.FromClaim(&claims, false)
	if _, err := child.state.GetUserByOIDCIdentifier(user.ProviderIdentifier.String); errors.Is(err, db.ErrUserNotFound) {
		if _, _, err := child.state.CreateUser(user); err != nil {
			return fail(err)
		}
	} else if err != nil {
		return fail(err)
	}
	if _, err := child.state.GetPolicy(); errors.Is(err, types.ErrPolicyNotFound) {
		if _, _, err := child.state.UpdatePolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)); err != nil {
			return fail(err)
		}
	} else if err != nil {
		return fail(err)
	}
	keyPath := filepath.Join(root, "headscale", "console-api-key")
	if data, err := os.ReadFile(keyPath); err == nil {
		item.apiKey = strings.TrimSpace(string(data))
		if valid, err := child.state.ValidateAPIKey(item.apiKey); err != nil || !valid {
			item.apiKey = ""
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if item.apiKey == "" {
		key, _, err := child.state.CreateAPIKey(nil)
		if err != nil {
			return fail(err)
		}
		if err := persistConsoleFile(keyPath, []byte(key+"\n")); err != nil {
			return fail(err)
		}
		item.apiKey = key
	}
	if dm := m.root.state.ConfiguredDERPMap(); dm.Valid() {
		child.state.SetDERPMap(dm.AsStruct())
	}
	for _, node := range child.state.ListEphemeralNodes().All() {
		child.ephemeralGC.Schedule(node.ID(), cfg.Node.Ephemeral.InactivityTimeout)
	}
	child.extraRecordMan, err = dns.NewExtraRecordsManager(cfg.DNSConfig.ExtraRecordsPath)
	if err != nil {
		return fail(err)
	}
	cfg.SetExtraRecords(child.extraRecordMan.Records())
	go child.extraRecordMan.Run()
	item.background.Add(1)
	go func() { defer item.background.Done(); child.scheduledTasks(ctx) }()
	data, err := json.Marshal(owner)
	if err != nil {
		return fail(err)
	}
	if err := persistConsoleFile(ownerPath, data); err != nil {
		return fail(err)
	}
	item.handler = child.HTTPHandler()
	m.items[owner.ID] = item
	return item, nil
}

func (m *consoleTailnets) initialConfig(root, path, id string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	config := make(map[string]any)
	if m.template != "" {
		data, err := os.ReadFile(m.template)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(data, &config); err != nil {
			return err
		}
	}
	baseDomain := m.root.cfg.BaseDomain
	if baseDomain == "" {
		baseDomain = "tailnet.internal"
	}
	dnsConfig, _ := config["dns"].(map[string]any)
	if dnsConfig == nil {
		dnsConfig = map[string]any{"magic_dns": true, "override_local_dns": true, "nameservers": map[string]any{"global": []string{"1.1.1.1"}}}
	}
	records := filepath.Join(root, "headscale", "extra-records.json")
	if _, err := os.Stat(records); errors.Is(err, os.ErrNotExist) {
		if err := persistConsoleFile(records, []byte("[]\n")); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	dnsConfig["base_domain"] = strings.TrimPrefix(id, "usr_") + "." + baseDomain
	dnsConfig["extra_records_path"] = records
	delete(dnsConfig, "extra_records")
	config["dns"] = dnsConfig
	config["policy"] = map[string]any{"mode": "database"}
	config["database"] = map[string]any{"type": "sqlite", "sqlite": map[string]any{"path": filepath.Join(root, "headscale", "db.sqlite"), "write_ahead_log": true}}
	config["unix_socket"] = filepath.Join(root, "headscale", "headscale.sock")
	if oidc, ok := config["oidc"].(map[string]any); ok {
		delete(oidc, "allowed_domains")
		delete(oidc, "allowed_users")
		delete(oidc, "allowed_groups")
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return persistConsoleFile(path, data)
}

func persistConsoleFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".console-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (m *consoleTailnets) remove(id string) error {
	lock := m.operation(id)
	lock.Lock()
	defer lock.Unlock()
	if !consoleOwnerID.MatchString(id) {
		return fmt.Errorf("invalid personal network owner")
	}
	m.mu.Lock()
	item := m.items[id]
	root := filepath.Join(m.dir, id)
	if err := os.MkdirAll(root, 0o700); err != nil {
		m.mu.Unlock()
		return err
	}
	data, _ := json.Marshal(consoleOwner{ID: id, Deleted: true})
	if err := persistConsoleFile(filepath.Join(root, "owner.json"), data); err != nil {
		m.mu.Unlock()
		return err
	}
	delete(m.items, id)
	m.mu.Unlock()
	if item != nil {
		item.close()
	}
	// Older Console releases placed all accounts in the root network. Revoke
	// this identity there too, including tagged devices whose UserID records
	// the creator. Other identities and their devices remain untouched.
	identity := (&types.OIDCClaims{Iss: m.root.cfg.OIDC.Issuer, Sub: id}).Identifier()
	legacyUser, err := m.root.state.GetUserByOIDCIdentifier(identity)
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return err
	}
	if legacyUser != nil {
		userID := types.UserID(legacyUser.ID)
		for _, node := range m.root.state.ListNodes().All() {
			if !node.UserID().Valid() || node.UserID().Get() != legacyUser.ID {
				continue
			}
			changes, err := m.root.state.DeleteNode(node)
			m.root.Change(changes...)
			if err != nil {
				return err
			}
		}
		change, err := m.root.state.DeleteUser(userID)
		m.root.Change(change)
		if err != nil {
			return err
		}
	}
	// Keep only a tombstone: stale OIDC callbacks must never recreate a deleted
	// account's network. All database, policy, DNS and credential files are purged.
	for _, name := range []string{"headscale", "headplane", "generated", "secrets"} {
		if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
			return err
		}
	}
	return nil
}

func (m *consoleTailnets) reload(id string) error {
	if !consoleOwnerID.MatchString(id) {
		return fmt.Errorf("invalid personal network owner")
	}
	lock := m.operation(id)
	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	item := m.items[id]
	if item == nil {
		m.mu.Unlock()
		return fmt.Errorf("personal network unavailable")
	}
	delete(m.items, id)
	m.mu.Unlock()
	item.close()
	_, err := m.ensureLocked(item.owner)
	return err
}

func (m *consoleTailnets) forAuth(id types.AuthID) *consoleNetwork {
	if item, ok := m.bindings.Get(id); ok {
		return item
	}
	for _, item := range m.snapshot() {
		if _, ok := item.h.state.GetAuthCacheEntry(id); ok {
			return item
		}
	}
	return nil
}

func (m *consoleTailnets) bind(id types.AuthID, target *consoleNetwork) error {
	entry, ok := m.root.state.GetAuthCacheEntry(id)
	if !ok {
		return fmt.Errorf("registration has expired")
	}
	if entry.IsRegistration() {
		if previous := m.forNode(entry.RegistrationData().NodeKey); previous != nil && previous != target {
			return fmt.Errorf("remove this device from its previous network before registering it again")
		}
	}
	if err := target.h.state.SetAuthCacheEntry(id, entry); err != nil {
		return err
	}
	m.bindings.Add(id, target)
	return nil
}

func (m *consoleTailnets) forNode(nodeKey key.NodePublic) *consoleNetwork {
	if nodeKey.IsZero() {
		return nil
	}
	for _, item := range m.snapshot() {
		if _, ok := item.h.state.GetNodeByNodeKey(nodeKey); ok {
			return item
		}
	}
	return nil
}

func (m *consoleTailnets) prepareIDs(owner string, state *state.State) error {
	users, err := state.ListAllUsers()
	if err != nil {
		return err
	}
	m.idMu.Lock()
	if m.ids == nil {
		m.ids = map[string]map[uint64]string{"user": {}, "node": {}}
	}
	reserve := func(kind string, id uint64) error {
		if previous, ok := m.ids[kind][id]; ok && previous != owner {
			return fmt.Errorf("public %s identity collides with another network", kind)
		}
		m.ids[kind][id] = owner
		return nil
	}
	for _, user := range users {
		if err := reserve("user", uint64(user.ID)); err != nil {
			m.idMu.Unlock()
			return err
		}
	}
	for _, node := range state.ListNodes().All() {
		if err := reserve("node", node.ID().Uint64()); err != nil {
			m.idMu.Unlock()
			return err
		}
	}
	m.idMu.Unlock()
	return state.UseGlobalIDs(func(kind string) (uint64, error) {
		m.idMu.Lock()
		defer m.idMu.Unlock()
		for {
			var random [8]byte
			if _, err := rand.Read(random[:]); err != nil {
				return 0, err
			}
			id := binary.LittleEndian.Uint64(random[:]) & ((1 << 53) - 1)
			if id == 0 || kind == "user" && id == types.TaggedDevicesUserID {
				continue
			}
			if _, exists := m.ids[kind][id]; exists {
				continue
			}
			m.ids[kind][id] = owner
			return id, nil
		}
	})
}

func (m *consoleTailnets) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/console/tailnet/reload" {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if ok {
				for _, item := range m.snapshot() {
					if valid, _ := item.h.state.ValidateAPIKey(token); valid {
						if err := m.reload(item.owner.ID); err != nil {
							http.Error(w, "Personal network reload failed", http.StatusServiceUnavailable)
						} else {
							w.WriteHeader(http.StatusNoContent)
						}
						return
					}
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodHead && r.URL.Path == "/machine/ping-response" {
			for _, item := range m.snapshot() {
				if item.h.state.CompletePing(r.URL.Query().Get("id")) {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/console/tailnets") {
			m.management(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method == http.MethodPost && r.URL.Path == "/api/v2/oauth/token" {
				body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
				if err != nil {
					http.Error(w, "Invalid token request", http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				form, _ := url.ParseQuery(string(body))
				secret := form.Get("client_secret")
				if secret == "" {
					_, secret, _ = r.BasicAuth()
				}
				if secret != "" {
					for _, item := range m.snapshot() {
						if _, err := item.h.state.AuthenticateOAuthClient(secret); err == nil {
							item.serve(w, r, item.handler)
							return
						}
					}
				}
			}
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if ok {
				for _, item := range m.snapshot() {
					if valid, _ := item.h.state.ValidateAPIKey(token); valid {
						item.serve(w, r, item.handler)
						return
					}
					if _, err := item.h.state.AuthenticateAccessToken(token); err == nil {
						item.serve(w, r, item.handler)
						return
					}
				}
			}
		}
		for _, prefix := range []string{"/register/confirm/", "/register/", "/auth/"} {
			if strings.HasPrefix(r.URL.Path, prefix) {
				if id, err := types.AuthIDFromString(strings.TrimPrefix(r.URL.Path, prefix)); err == nil {
					if item := m.forAuth(id); item != nil {
						item.serve(w, r, item.handler)
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (m *consoleTailnets) management(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if valid, _ := m.root.state.ValidateAPIKey(token); !valid {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodDelete {
		id := strings.TrimPrefix(r.URL.Path, "/api/console/tailnets/")
		if err := m.remove(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/api/console/tailnets" {
		http.NotFound(w, r)
		return
	}
	var owner consoleOwner
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&owner); err != nil {
		http.Error(w, "Invalid owner", http.StatusBadRequest)
		return
	}
	owner.Deleted = false
	item, err := m.ensure(owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": item.owner.ID, "api_key": item.apiKey, "config_path": item.configPath})
}

type consoleNoiseScope struct {
	mu      sync.Mutex
	network *consoleNetwork
}

func (ns *noiseServer) consoleHandler(handler func(*noiseServer, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		manager := ns.headscale.console
		if manager == nil {
			handler(ns, w, r)
			return
		}
		var target *consoleNetwork
		if strings.HasPrefix(r.URL.Path, "/machine/ssh/action/") {
			if id, err := strconv.ParseUint(chi.URLParam(r, "dst_node_id"), 10, 64); err == nil {
				for _, item := range manager.snapshot() {
					if node, ok := item.h.state.GetNodeByID(types.NodeID(id)); ok {
						if node.MachineKey() != ns.machineKey {
							http.Error(w, "Node not found", http.StatusNotFound)
							return
						}
						target = item
						break
					}
				}
			}
		}
		if r.URL.Path == "/machine/c2n-response" {
			for _, item := range manager.snapshot() {
				if _, ok := item.h.state.C2NTarget(r.URL.Query().Get("id")); ok {
					target = item
					break
				}
			}
		}
		if r.URL.Path == "/machine/register" || r.URL.Path == "/machine/map" || r.URL.Path == "/machine/set-dns" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var routing struct {
				NodeKey    key.NodePublic
				OldNodeKey key.NodePublic
				Followup   string
				Auth       *struct{ AuthKey string }
			}
			if json.Unmarshal(body, &routing) == nil {
				target = manager.forNode(routing.NodeKey)
				lookupKey := routing.NodeKey
				if target == nil && r.URL.Path == "/machine/register" && !routing.OldNodeKey.IsZero() {
					target = manager.forNode(routing.OldNodeKey)
					lookupKey = routing.OldNodeKey
				}
				if target != nil {
					node, _ := target.h.state.GetNodeByNodeKey(lookupKey)
					if node.MachineKey() != ns.machineKey {
						http.Error(w, "Node not found", http.StatusNotFound)
						return
					}
				}
				if target == nil && r.URL.Path == "/machine/register" && routing.Auth != nil && routing.Auth.AuthKey != "" {
					for _, item := range manager.snapshot() {
						if _, err := item.h.state.GetPreAuthKey(routing.Auth.AuthKey); err == nil {
							target = item
							break
						}
					}
				}
				if target == nil && routing.Followup != "" {
					parts := strings.Split(routing.Followup, "/register/")
					if len(parts) == 2 {
						if id, err := types.AuthIDFromString(parts[1]); err == nil {
							target = manager.forAuth(id)
						}
					}
				}
			}
		}
		ns.consoleScope.mu.Lock()
		if target == nil {
			target = ns.consoleScope.network
		}
		if target != nil && ns.consoleScope.network != nil && target != ns.consoleScope.network && target.owner.ID != ns.consoleScope.network.owner.ID {
			ns.consoleScope.mu.Unlock()
			http.Error(w, "Reconnect before switching networks", http.StatusForbidden)
			return
		}
		if target != nil {
			ns.consoleScope.network = target
		}
		ns.consoleScope.mu.Unlock()
		if target == nil {
			handler(ns, w, r)
			return
		}
		copy := *ns
		copy.headscale = target.h
		target.serve(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler(&copy, w, r) }))
	}
}
