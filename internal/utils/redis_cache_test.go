package utils

import (
	"bufio"
	"context"
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
type fakeRedisServer struct {
	ln       net.Listener
	mu       sync.Mutex
	data     map[string]string
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
		data:     make(map[string]string),
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
			v, ok := s.data[args[1]]
			s.mu.Unlock()
			if ok {
				_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(v), v)
			} else {
				_, _ = fmt.Fprintf(conn, "$-1\r\n")
			}
		case "SET":
			s.mu.Lock()
			s.data[args[1]] = args[2]
			s.mu.Unlock()
			_, _ = fmt.Fprintf(conn, "+OK\r\n")
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
	for i := 0; i < n; i++ {
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
