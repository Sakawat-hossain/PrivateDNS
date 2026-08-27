package resolver

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Blocklist holds the compiled set of blocked names. Lists are parsed once
// into a hash set and swapped atomically, so a reload never blocks queries.
type Blocklist struct {
	dir string
	set atomic.Pointer[map[string]struct{}]
}

func NewBlocklist(dir string) *Blocklist {
	b := &Blocklist{dir: dir}
	empty := map[string]struct{}{}
	b.set.Store(&empty)
	return b
}

// Load reads every *.txt file in the directory. Both plain domain lists and
// hosts-format files ("0.0.0.0 ads.example.com") are accepted, which covers
// the common feeds without needing a per-source parser.
func (b *Blocklist) Load() (int, error) {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // no lists configured yet is not an error
		}
		return 0, err
	}

	set := make(map[string]struct{}, 1<<20)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		if err := loadListFile(filepath.Join(b.dir, e.Name()), set); err != nil {
			return 0, err
		}
	}

	b.set.Store(&set)
	return len(set), nil
}

func loadListFile(path string, set map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		// hosts format: strip a leading address and keep the name
		if fields := strings.Fields(line); len(fields) >= 2 {
			switch fields[0] {
			case "0.0.0.0", "127.0.0.1", "::", "::1":
				line = fields[1]
			default:
				line = fields[0]
			}
		}
		name := normalizeDomain(line)
		if name == "" || strings.ContainsAny(name, "/ *:") {
			continue
		}
		// Every hosts file opens with the loopback preamble -- "127.0.0.1
		// localhost", "::1 ip6-localhost" and friends. Those are declarations
		// about the local machine, not things to block, and a resolver that
		// blocks localhost because a feed mentioned it is broken.
		if neverBlock[name] {
			continue
		}
		set[name] = struct{}{}
	}
	return sc.Err()
}

// Blocked reports whether the name or any parent domain is listed.
func (b *Blocklist) Blocked(name string) bool {
	set := *b.set.Load()
	if len(set) == 0 {
		return false
	}
	for _, suffix := range domainSuffixes(name) {
		if _, ok := set[suffix]; ok {
			return true
		}
	}
	return false
}

func (b *Blocklist) Size() int { return len(*b.set.Load()) }

// WatchReload re-reads the lists on a timer so updating a feed does not
// require a restart or drop a single connection.
func (b *Blocklist) WatchReload(every time.Duration, onReload func(int, error)) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			n, err := b.Load()
			if onReload != nil {
				onReload(n, err)
			}
		}
	}()
}

// neverBlock are names no feed may filter, whatever it says.
//
// Hosts files all begin with the loopback preamble, and the parser above reads
// "127.0.0.1 localhost" as an instruction to block localhost. They are also the
// names most likely to break something quietly if a feed ever listed them by
// mistake.
var neverBlock = map[string]bool{}

func init() {
	for _, n := range []string{
		"localhost", "localhost.localdomain", "local",
		"broadcasthost", "ip6-localhost", "ip6-loopback",
		"ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
	} {
		neverBlock[n] = true
	}
}
