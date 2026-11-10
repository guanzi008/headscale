package db

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
)

var (
	errGeneratedIPBytesInvalid = errors.New("generated ip bytes are invalid ip")
	errGeneratedIPNotInPrefix  = errors.New("generated ip not in prefix")
	errIPAllocatorNil          = errors.New("ip allocator was nil")
)

// IPAllocator is a singleton responsible for allocating
// IP addresses for nodes and making sure the same
// address is not handed out twice. There can only be one
// and it needs to be created before any other database
// writes occur.
type IPAllocator struct {
	mu sync.Mutex

	prefix4 *netip.Prefix
	prefix6 *netip.Prefix

	// Previous IPs handed out
	prev4 netip.Addr
	prev6 netip.Addr

	// strategy used for handing out IP addresses.
	strategy types.IPAllocationStrategy

	// Set of all IPs handed out.
	// This might not be in sync with the database,
	// but it is more conservative. If saves to the
	// database fails, the IP will be allocated here
	// until the next restart of Headscale.
	usedIPs netipx.IPSetBuilder

	// reservedPools are nodeAttrs.ipPool ranges owned by users. Global
	// allocation must never hand out an address inside one, while an
	// explicit user pool allocation may use its own range.
	reservedPools netipx.IPSet
}

// NewIPAllocator returns a new [IPAllocator] singleton which
// can be used to hand out unique IP addresses within the
// provided IPv4 and IPv6 prefix. It needs to be created
// when headscale starts and needs to finish its read
// transaction before any writes to the database occur.
func NewIPAllocator(
	db *HSDatabase,
	prefix4, prefix6 *netip.Prefix,
	strategy types.IPAllocationStrategy,
) (*IPAllocator, error) {
	ret := IPAllocator{
		prefix4: prefix4,
		prefix6: prefix6,

		strategy: strategy,
	}

	var (
		v4s []sql.NullString
		v6s []sql.NullString
	)

	if db != nil {
		err := db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv4", &v4s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv4 addresses from database: %w", err)
		}

		err = db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv6", &v6s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv6 addresses from database: %w", err)
		}
	}

	var ips netipx.IPSetBuilder

	// Add network and broadcast addrs to used pool so they
	// are not handed out to nodes.
	if prefix4 != nil {
		network4, broadcast4 := util.GetIPPrefixEndpoints(*prefix4)
		ips.Add(network4)
		ips.Add(broadcast4)

		// Use network as starting point, it will be used to call .Next()
		// TODO(kradalby): Could potentially take all the IPs loaded from
		// the database into account to start at a more "educated" location.
		ret.prev4 = network4
	}

	if prefix6 != nil {
		network6, broadcast6 := util.GetIPPrefixEndpoints(*prefix6)
		ips.Add(network6)
		ips.Add(broadcast6)

		ret.prev6 = network6
	}

	// Fetch all the IP Addresses currently handed out from the Database
	// and add them to the used IP set.
	for _, addrStr := range append(v4s, v6s...) {
		if addrStr.Valid {
			addr, err := netip.ParseAddr(addrStr.String)
			if err != nil {
				return nil, fmt.Errorf("parsing IP address from database: %w", err)
			}

			ips.Add(addr)
		}
	}

	// Build the initial IPSet to validate that we can use it.
	_, err := ips.IPSet()
	if err != nil {
		return nil, fmt.Errorf(
			"building initial IP Set: %w",
			err,
		)
	}

	ret.usedIPs = ips

	return &ret, nil
}

func (i *IPAllocator) Next() (*netip.Addr, *netip.Addr, error) {
	return i.NextForPools(nil, nil)
}

// SetReservedPools replaces the user address ranges that tailnet-wide
// allocation must skip. Custom pool allocation uses the requested pool
// directly, so a node can still receive an address reserved for its owner.
func (i *IPAllocator) SetReservedPools(prefixes []netip.Prefix) error {
	var builder netipx.IPSetBuilder

	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return fmt.Errorf("invalid reserved IP pool %q", prefix)
		}

		builder.AddPrefix(prefix.Masked())
	}

	set, err := builder.IPSet()
	if err != nil {
		return fmt.Errorf("building reserved IP pools: %w", err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	i.reservedPools = *set

	return nil
}

// NextForPools allocates one address of each configured family. A non-empty
// pool list replaces the tailnet-wide prefix for that family, so a user can
// never escape their assigned range by exhausting it. Both addresses are
// reserved under one lock and rolled back together when either family fails.
func (i *IPAllocator) NextForPools(pools4, pools6 []netip.Prefix) (*netip.Addr, *netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var (
		err  error
		ret4 *netip.Addr
		ret6 *netip.Addr
	)

	prev4 := i.prev4
	custom4 := len(pools4) > 0

	if custom4 {
		ret4, err = i.allocateFromPoolsLocked(pools4)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv4 address: %w", err)
		}
	} else if i.prefix4 != nil {
		ret4, err = i.allocateNextLocked(&i.prev4, i.prefix4)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv4 address: %w", err)
		}
	}

	if len(pools6) > 0 {
		ret6, err = i.allocateFromPoolsLocked(pools6)
		if err != nil {
			if ret4 != nil {
				i.usedIPs.Remove(*ret4)
				if !custom4 {
					i.prev4 = prev4
				}
			}

			return nil, nil, fmt.Errorf("allocating IPv6 address: %w", err)
		}
	} else if i.prefix6 != nil {
		ret6, err = i.allocateNextLocked(&i.prev6, i.prefix6)
		if err != nil {
			// ret4 never reaches a caller, so nothing would ever free it, and
			// sequential allocation does not wrap back to it on its own.
			if ret4 != nil {
				i.usedIPs.Remove(*ret4)
				i.prev4 = prev4
			}

			return nil, nil, fmt.Errorf("allocating IPv6 address: %w", err)
		}
	}

	return ret4, ret6, nil
}

// NextForPool allocates one address for a single family. It is used when
// backfilling a node that is missing only one address family.
func (i *IPAllocator) NextForPool(ipv4 bool, pools []netip.Prefix) (*netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if len(pools) > 0 {
		return i.allocateFromPoolsLocked(pools)
	}

	prefix := i.prefix6
	prev := &i.prev6
	if ipv4 {
		prefix = i.prefix4
		prev = &i.prev4
	}

	if prefix == nil {
		return nil, nil
	}

	return i.allocateNextLocked(prev, prefix)
}

var ErrCouldNotAllocateIP = errors.New("failed to allocate IP")

func (i *IPAllocator) allocateFromPoolsLocked(prefixes []netip.Prefix) (*netip.Addr, error) {
	var lastErr error

	for _, prefix := range prefixes {
		addr, err := i.allocateFromPoolLocked(prefix)
		if err == nil {
			return addr, nil
		}

		lastErr = err
	}

	if lastErr == nil {
		lastErr = ErrCouldNotAllocateIP
	}

	return nil, lastErr
}

func (i *IPAllocator) allocateFromPoolLocked(prefix netip.Prefix) (*netip.Addr, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("%w: invalid prefix %q", ErrCouldNotAllocateIP, prefix)
	}

	rang := netipx.RangeOfPrefix(prefix.Masked())
	start := rang.From().Next()
	if !prefix.Contains(start) || start == rang.To() {
		return nil, ErrCouldNotAllocateIP
	}

	set, err := i.usedIPs.IPSet()
	if err != nil {
		return nil, err
	}

	for addr := start; prefix.Contains(addr) && addr != rang.To(); addr = addr.Next() {
		if !set.Contains(addr) && !isTailscaleReservedIP(addr) {
			i.usedIPs.Add(addr)

			return &addr, nil
		}
	}

	return nil, ErrCouldNotAllocateIP
}

// allocateNext allocates the next address from prefix under i.mu, advancing
// prev so a run of allocations (e.g. BackfillNodeIPs) does not rescan
// already-issued addresses, and so prev is read under the lock rather than in
// the caller's frame.
func (i *IPAllocator) allocateNext(prev *netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.allocateNextLocked(prev, prefix)
}

// allocateNextLocked is [IPAllocator.allocateNext] for a caller holding i.mu.
func (i *IPAllocator) allocateNextLocked(prev *netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	ret, err := i.next(*prev, prefix)
	if err != nil {
		return nil, err
	}

	*prev = *ret

	return ret, nil
}

func (i *IPAllocator) next(prev netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	var (
		err error
		ip  netip.Addr
	)

	switch i.strategy {
	case types.IPAllocationStrategySequential:
		// Get the first IP in our prefix
		ip = prev.Next()
	case types.IPAllocationStrategyRandom:
		ip, err = randomNext(*prefix)
		if err != nil {
			return nil, fmt.Errorf("getting random IP: %w", err)
		}
	}

	set, err := i.usedIPs.IPSet()
	if err != nil {
		return nil, err
	}

	// Subtract whole ranges before choosing an address. Walking every address
	// in a reserved IPv6 /64 would hold mu for effectively unbounded time.
	var available netipx.IPSetBuilder
	available.AddPrefix(*prefix)
	available.RemoveSet(set)
	available.RemoveSet(&i.reservedPools)
	available.RemovePrefix(tsaddr.ChromeOSVMRange())
	available.Remove(tsaddr.TailscaleServiceIP())
	available.Remove(tsaddr.TailscaleServiceIPv6())
	free, err := available.IPSet()
	if err != nil {
		return nil, err
	}
	ranges := free.Ranges()
	if len(ranges) == 0 {
		return nil, ErrCouldNotAllocateIP
	}

	if !prefix.Contains(ip) {
		ip = prefix.Masked().Addr()
	}

	for _, rang := range ranges {
		if rang.Contains(ip) {
			i.usedIPs.Add(ip)

			return &ip, nil
		}
		if rang.From().Compare(ip) > 0 {
			next := rang.From()
			i.usedIPs.Add(next)

			return &next, nil
		}
	}

	// No free range follows the cursor; reuse an address behind it.
	next := ranges[0].From()
	i.usedIPs.Add(next)

	return &next, nil
}

func randomNext(pfx netip.Prefix) (netip.Addr, error) {
	rang := netipx.RangeOfPrefix(pfx)
	fromIP, toIP := rang.From(), rang.To()

	var from, to big.Int

	from.SetBytes(fromIP.AsSlice())
	to.SetBytes(toIP.AsSlice())

	// Find the max, this is how we can do "random range",
	// get the "max" as 0 -> to - from and then add back from
	// after.
	tempMax := big.NewInt(0).Sub(&to, &from)

	// A single-address prefix (/32 or /128) has from == to, so tempMax is 0 and
	// rand.Int would panic on a non-positive bound. Return the sole address.
	if tempMax.Sign() <= 0 {
		return fromIP, nil
	}

	out, err := rand.Int(rand.Reader, tempMax)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("generating random IP: %w", err)
	}

	valInRange := big.NewInt(0).Add(&from, out)

	// big.Int.Bytes() strips leading zero bytes, so a value with a zero high
	// byte yields a too-short slice that AddrFromSlice rejects. Pad to the
	// prefix's address width.
	ip, ok := netip.AddrFromSlice(valInRange.FillBytes(make([]byte, len(fromIP.AsSlice()))))
	if !ok {
		return netip.Addr{}, errGeneratedIPBytesInvalid
	}

	if !pfx.Contains(ip) {
		return netip.Addr{}, fmt.Errorf(
			"%w: ip(%s) not in prefix(%s)",
			errGeneratedIPNotInPrefix,
			ip.String(),
			pfx.String(),
		)
	}

	return ip, nil
}

func isTailscaleReservedIP(ip netip.Addr) bool {
	return tsaddr.ChromeOSVMRange().Contains(ip) ||
		tsaddr.TailscaleServiceIP() == ip ||
		tsaddr.TailscaleServiceIPv6() == ip
}

// BackfillNodeIPs will take a database transaction, and
// iterate through all of the current nodes ([types.Node]) in headscale
// and ensure it has IP addresses according to the current
// configuration.
// This means that if both IPv4 and IPv6 is set in the
// config, and some nodes are missing that type of IP,
// it will be added.
// If a prefix type has been removed (IPv4 or IPv6), it
// will remove the IPs in that family from the node.
func (db *HSDatabase) BackfillNodeIPs(i *IPAllocator) ([]string, error) {
	return db.BackfillNodeIPsWithPools(i, nil)
}

// BackfillNodeIPsWithPools is [HSDatabase.BackfillNodeIPs] with per-user
// nodeAttrs.ipPool resolution. poolForUser may be nil for the legacy
// tailnet-wide behavior.
func (db *HSDatabase) BackfillNodeIPsWithPools(
	i *IPAllocator,
	poolForUser func(types.UserID) []netip.Prefix,
) ([]string, error) {
	var (
		err error
		ret []string
	)

	err = db.Write(func(tx *gorm.DB) error {
		if i == nil {
			return fmt.Errorf("backfilling IPs: %w", errIPAllocatorNil)
		}

		log.Trace().Caller().Msgf("starting to backfill IPs")

		nodes, err := ListNodes(tx)
		if err != nil {
			return fmt.Errorf("listing nodes to backfill IPs: %w", err)
		}

		for _, node := range nodes {
			log.Trace().Caller().EmbedObject(node).Msg("ip backfill check started because node found in database")

			var pools4, pools6 []netip.Prefix
			if poolForUser != nil && node.UserID != nil && !node.IsTagged() {
				for _, pool := range poolForUser(types.UserID(*node.UserID)) {
					if pool.Addr().Is4() {
						pools4 = append(pools4, pool)
					} else {
						pools6 = append(pools6, pool)
					}
				}
			}

			want4 := i.prefix4 != nil || len(pools4) > 0
			want6 := i.prefix6 != nil || len(pools6) > 0
			changed := false
			// IPv4 is configured for this node, but its address is missing.
			if want4 && node.IPv4 == nil {
				ret4, err := i.NextForPool(true, pools4)
				if err != nil {
					return fmt.Errorf("allocating IPv4 for node(%d): %w", node.ID, err)
				}

				node.IPv4 = ret4
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv4 %q to Node(%d) %q", ret4.String(), node.ID, node.Hostname))
			}

			// IPv6 is configured for this node, but its address is missing.
			if want6 && node.IPv6 == nil {
				ret6, err := i.NextForPool(false, pools6)
				if err != nil {
					return fmt.Errorf("allocating IPv6 for node(%d): %w", node.ID, err)
				}

				node.IPv6 = ret6
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv6 %q to Node(%d) %q", ret6.String(), node.ID, node.Hostname))
			}

			// IPv4 is no longer configured for this node, but it has an IP.
			if !want4 && node.IPv4 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv4 %q from Node(%d) %q", node.IPv4.String(), node.ID, node.Hostname))
				node.IPv4 = nil
				changed = true
			}

			// IPv6 is no longer configured for this node, but it has an IP.
			if !want6 && node.IPv6 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv6 %q from Node(%d) %q", node.IPv6.String(), node.ID, node.Hostname))
				node.IPv6 = nil
				changed = true
			}

			if changed {
				// Use Updates() with Select() to only update IP fields, avoiding overwriting
				// other fields like Expiry. We need Select() because Updates() alone skips
				// zero values, but we DO want to update IPv4/IPv6 to nil when removing them.
				err := tx.Model(node).Select("ipv4", "ipv6").Updates(node).Error
				if err != nil {
					return fmt.Errorf("saving node(%d) after adding IPs: %w", node.ID, err)
				}
			}
		}

		return nil
	})

	return ret, err
}

func (i *IPAllocator) FreeIPs(ips []netip.Addr) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, ip := range ips {
		i.usedIPs.Remove(ip)
	}
}
