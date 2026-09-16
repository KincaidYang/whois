package utils

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeRedisServer speaks just enough RESP2 for the go-redis client: HELLO is
// rejected so the client downgrades from RESP3, PING/GET/SET behave, and any
// command can be scripted to fail so error paths are reachable without a
// real Redis.
type fakeRedisEntry struct {
	value     string
	expiresAt time.Time // zero = no expiry
}

type fakeRedisServer struct {
	ln       net.Listener
	mu       sync.Mutex
	data     map[string]fakeRedisEntry
	failCmds map[string]bool
}

func newFakeRedisServer(t *testing.T) *fakeRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeRedisServer{
		ln:       ln,
		data:     make(map[string]fakeRedisEntry),
		failCmds: make(map[string]bool),
	}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeRedisServer) addr() string { return s.ln.Addr().String() }

func (s *fakeRedisServer) setFail(cmd string, fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failCmds[strings.ToUpper(cmd)] = fail
}

func (s *fakeRedisServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *fakeRedisServer) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])

		s.mu.Lock()
		fail := s.failCmds[cmd]
		s.mu.Unlock()
		if fail {
			_, _ = fmt.Fprintf(conn, "-ERR scripted failure for %s\r\n", cmd)
			continue
		}

		switch cmd {
		case "HELLO":
			// Force the client down to RESP2, like pre-6.0 servers.
			_, _ = fmt.Fprintf(conn, "-ERR unknown command 'HELLO'\r\n")
		case "PING":
			_, _ = fmt.Fprintf(conn, "+PONG\r\n")
		case "GET":
			s.mu.Lock()
			e, ok := s.data[args[1]]
			s.mu.Unlock()
			if ok {
				_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(e.value), e.value)
			} else {
				_, _ = fmt.Fprintf(conn, "$-1\r\n")
			}
		case "SET":
			e := fakeRedisEntry{value: args[2]}
			// Parse the EX/PX option go-redis sends for a Set(...,
			// expiration) call, so TTL can report something meaningful.
			for i := 3; i < len(args); i++ {
				switch strings.ToUpper(args[i]) {
				case "EX":
					if i+1 < len(args) {
						if secs, err := strconv.Atoi(args[i+1]); err == nil {
							e.expiresAt = time.Now().Add(time.Duration(secs) * time.Second)
						}
						i++
					}
				case "PX":
					if i+1 < len(args) {
						if ms, err := strconv.Atoi(args[i+1]); err == nil {
							e.expiresAt = time.Now().Add(time.Duration(ms) * time.Millisecond)
						}
						i++
					}
				}
			}
			s.mu.Lock()
			s.data[args[1]] = e
			s.mu.Unlock()
			_, _ = fmt.Fprintf(conn, "+OK\r\n")
		case "PTTL":
			s.mu.Lock()
			e, ok := s.data[args[1]]
			s.mu.Unlock()
			switch {
			case !ok:
				_, _ = fmt.Fprintf(conn, ":-2\r\n")
			case e.expiresAt.IsZero():
				_, _ = fmt.Fprintf(conn, ":-1\r\n")
			default:
				remaining := int(time.Until(e.expiresAt).Milliseconds())
				if remaining < 0 {
					remaining = 0
				}
				_, _ = fmt.Fprintf(conn, ":%d\r\n", remaining)
			}
		case "DEL":
			s.mu.Lock()
			n := 0
			for _, k := range args[1:] {
				if _, ok := s.data[k]; ok {
					delete(s.data, k)
					n++
				}
			}
			s.mu.Unlock()
			_, _ = fmt.Fprintf(conn, ":%d\r\n", n)
		default:
			// CLIENT SETINFO, SELECT, ... — acknowledge and move on.
			_, _ = fmt.Fprintf(conn, "+OK\r\n")
		}
	}
}

// readRESPCommand parses one client command (an array of bulk strings).
func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := respLine(r)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("unexpected line %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for range n {
		bulk, err := respLine(r)
		if err != nil {
			return nil, err
		}
		if len(bulk) == 0 || bulk[0] != '$' {
			return nil, fmt.Errorf("unexpected bulk header %q", bulk)
		}
		l, err := strconv.Atoi(bulk[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2) // payload + trailing \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

func respLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func newTestRedisCache(t *testing.T, addr string) *RedisCache {
	t.Helper()
	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		DialTimeout: time.Second,
		ReadTimeout: time.Second,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = client.Close() })
	rc := NewRedisCache(client)
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

func TestRedisCacheBasic(t *testing.T) {
	ctx := context.Background()
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())

	if !rc.IsHealthy() {
		t.Fatal("cache must be healthy after a successful initial ping")
	}

	r, err := rc.Get(ctx, "missing")
	if err != nil || r.Found {
		t.Errorf("Get(missing) = %+v, %v; want clean miss", r, err)
	}

	if err := rc.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	r, err = rc.Get(ctx, "k")
	if err != nil || !r.Found || r.Data != "v" {
		t.Errorf("Get(k) = %+v, %v; want hit with v", r, err)
	}
}

// TestRedisCacheGetReturnsExpiresAt verifies Get reports the entry's
// remaining TTL (read back via a pipelined TTL alongside the GET), and that
// a key with no TTL (matching Redis's "exists but no expiry" TTL of -1)
// leaves ExpiresAt zero rather than reporting a bogus one.
func TestRedisCacheGetReturnsExpiresAt(t *testing.T) {
	ctx := context.Background()
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())

	if err := rc.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	before := time.Now()
	r, err := rc.Get(ctx, "k")
	if err != nil || !r.Found {
		t.Fatalf("Get(k) = %+v, %v; want a hit", r, err)
	}
	if r.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt must be populated for a key with a TTL")
	}
	wantExpiry := before.Add(time.Minute)
	if diff := r.ExpiresAt.Sub(wantExpiry); diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("ExpiresAt = %v, want close to %v", r.ExpiresAt, wantExpiry)
	}

	// A key stored without going through Set's expiration (simulating one
	// with no TTL) must not get a fabricated ExpiresAt.
	s.mu.Lock()
	s.data["no-ttl"] = fakeRedisEntry{value: "v"}
	s.mu.Unlock()
	r, err = rc.Get(ctx, "no-ttl")
	if err != nil || !r.Found {
		t.Fatalf("Get(no-ttl) = %+v, %v; want a hit", r, err)
	}
	if !r.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero for a key with no TTL", r.ExpiresAt)
	}
}

// TestRedisCacheGetTreatsExpiringKeyAsStale verifies a key with essentially
// no time left (PTTL <= 0, e.g. it expired or was deleted in the race
// between the pipelined GET and PTTL) is treated as already expiring rather
// than as "unknown" — which serveFromCache would otherwise read as "use the
// full configured TTL", handing a stale-adjacent value a fresh hour of
// downstream Cache-Control freshness.
func TestRedisCacheGetTreatsExpiringKeyAsStale(t *testing.T) {
	ctx := context.Background()
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())

	s.mu.Lock()
	s.data["k"] = fakeRedisEntry{value: "v", expiresAt: time.Now().Add(-time.Hour)}
	s.mu.Unlock()

	before := time.Now()
	r, err := rc.Get(ctx, "k")
	if err != nil || !r.Found || r.Data != "v" {
		t.Fatalf("Get(k) = %+v, %v; want a hit", r, err)
	}
	if r.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt must not be left unknown for a key that's already expiring")
	}
	if diff := r.ExpiresAt.Sub(before); diff < -time.Second || diff > time.Second {
		t.Errorf("ExpiresAt = %v, want close to now (already expiring), not a fabricated full TTL", r.ExpiresAt)
	}
}

func TestRedisCacheErrorFlipsHealth(t *testing.T) {
	ctx := context.Background()
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())

	// A server-side GET error must mark the connection unhealthy.
	s.setFail("GET", true)
	if _, err := rc.Get(ctx, "k"); err == nil {
		t.Fatal("expected error from scripted GET failure")
	}
	if rc.IsHealthy() {
		t.Fatal("a Redis error must flip the health flag off")
	}

	// While unhealthy, Get short-circuits to a miss and Set is a silent no-op.
	if r, err := rc.Get(ctx, "k"); err != nil || r.Found {
		t.Errorf("unhealthy Get = %+v, %v; want silent miss", r, err)
	}
	if err := rc.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Errorf("unhealthy Set = %v; want silent nil", err)
	}

	// A later health check against a recovered server restores service.
	s.setFail("GET", false)
	rc.checkHealth(false)
	if !rc.IsHealthy() {
		t.Fatal("health must recover after a successful ping")
	}

	// SET errors flip health too.
	s.setFail("SET", true)
	if err := rc.Set(ctx, "k", "v", time.Minute); err == nil {
		t.Fatal("expected error from scripted SET failure")
	}
	if rc.IsHealthy() {
		t.Error("a SET error must flip the health flag off")
	}
}

func TestRedisCacheHealthLostAndRestored(t *testing.T) {
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())

	s.setFail("PING", true)
	rc.checkHealth(false) // "connection lost" transition
	if rc.IsHealthy() {
		t.Fatal("failed ping must mark the cache unhealthy")
	}

	s.setFail("PING", false)
	rc.checkHealth(false) // "connection restored" transition
	if !rc.IsHealthy() {
		t.Fatal("successful ping must mark the cache healthy again")
	}
}

func TestRedisCacheCancelledContextKeepsHealth(t *testing.T) {
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// One caller's aborted request must not poison the shared health flag.
	if _, err := rc.Get(ctx, "k"); err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !rc.IsHealthy() {
		t.Error("cancelled Get must not flip health")
	}
	if err := rc.Set(ctx, "k", "v", time.Minute); err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !rc.IsHealthy() {
		t.Error("cancelled Set must not flip health")
	}
	if err := rc.Del(ctx, "k"); err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !rc.IsHealthy() {
		t.Error("cancelled Del must not flip health")
	}
}

// TestRedisCacheDel verifies Del removes keys outright and is a silent no-op
// when unhealthy or given no keys, matching Set's existing behavior.
func TestRedisCacheDel(t *testing.T) {
	ctx := context.Background()
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())

	if err := rc.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := rc.Del(ctx, "k", "missing"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if r, _ := rc.Get(ctx, "k"); r.Found {
		t.Error("k should be gone after Del")
	}

	if err := rc.Del(ctx); err != nil {
		t.Errorf("Del with no keys = %v, want silent nil", err)
	}

	// A server-side DEL error must flip health off, like GET/SET failures do.
	s.setFail("DEL", true)
	if err := rc.Del(ctx, "k"); err == nil {
		t.Fatal("expected error from scripted DEL failure")
	}
	if rc.IsHealthy() {
		t.Error("a DEL error must flip the health flag off")
	}

	s.setFail("DEL", false)
	rc.checkHealth(false)
	s.setFail("PING", true)
	rc.checkHealth(false)
	// Unlike Set, an unhealthy Del must report that it did nothing rather
	// than silently succeeding: FallbackCache.flushDirty uses the return
	// value to decide whether a key was actually purged from primary.
	if err := rc.Del(ctx, "k"); !errors.Is(err, errRedisUnhealthy) {
		t.Errorf("unhealthy Del = %v, want errRedisUnhealthy", err)
	}
}

func TestRedisCacheUnavailableAtStart(t *testing.T) {
	// Grab a port that refuses connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	rc := newTestRedisCache(t, addr)
	if rc.IsHealthy() {
		t.Fatal("cache must start unhealthy when Redis is unreachable")
	}
}

func TestRedisCacheCloseIdempotent(t *testing.T) {
	s := newFakeRedisServer(t)
	rc := newTestRedisCache(t, s.addr())
	if err := rc.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
