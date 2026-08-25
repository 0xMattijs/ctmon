package source

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const sampleUpdate = `{
  "message_type": "certificate_update",
  "data": {
    "leaf_cert": {
      "subject": {"CN": "*.example.com"},
      "issuer": {"CN": "R3", "O": "Let's Encrypt"},
      "not_before": 1755000000.0,
      "not_after": 1762776000.0
    },
    "source": {"name": "Google 'Argon2026h1'"},
    "seen": 1755000123.5
  }
}`

const sampleHeartbeat = `{"message_type": "heartbeat", "timestamp": 1755000123.5}`

// wsServer serves the given messages to one client and then holds the
// connection open until the test finishes.
func wsServer(t *testing.T, msgs ...string) string {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for _, m := range msgs {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(m)); err != nil {
				return
			}
		}
		// Block until the client goes away.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func TestCertstreamParsesUpdates(t *testing.T) {
	url := wsServer(t, sampleHeartbeat, sampleUpdate, `{"message_type":"certificate_update","data":{}}`)

	cs := &Certstream{
		URL: url,
		Log: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan Cert, 4)
	go cs.Run(ctx, out)

	var got Cert
	select {
	case got = <-out:
	case <-ctx.Done():
		t.Fatal("no certificate arrived before the deadline")
	}

	if got.CN != "*.example.com" {
		t.Errorf("CN = %q, want *.example.com", got.CN)
	}
	if got.Issuer != "R3" {
		t.Errorf("issuer = %q, want R3", got.Issuer)
	}
	if got.Source != "certstream" || got.Index != -1 {
		t.Errorf("source = %q index = %d", got.Source, got.Index)
	}
	if got.NotBefore.Unix() != 1755000000 {
		t.Errorf("not_before = %v", got.NotBefore)
	}
	if got.SeenAt.IsZero() {
		t.Error("SeenAt was not set")
	}

	// The heartbeat and the CN-less update must not have produced entries.
	select {
	case extra := <-out:
		t.Errorf("unexpected extra cert: %+v", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	base, max := time.Second, 30*time.Second
	if d := backoff(0, base, max); d != time.Second {
		t.Errorf("backoff(0) = %v, want 1s", d)
	}
	if d := backoff(3, base, max); d != 8*time.Second {
		t.Errorf("backoff(3) = %v, want 8s", d)
	}
	if d := backoff(20, base, max); d != max {
		t.Errorf("backoff(20) = %v, want the %v cap", d, max)
	}
}

// flakyWSServer serves one message per connection and then hangs up, so a
// client that does not reconnect sees exactly one certificate.
func flakyWSServer(t *testing.T, msg string) (url string, conns func() int) {
	t.Helper()
	var (
		mu sync.Mutex
		n  int
	)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		mu.Lock()
		n++
		mu.Unlock()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(msg))
		conn.Close()
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func TestCertstreamReconnects(t *testing.T) {
	url, conns := flakyWSServer(t, sampleUpdate)

	cs := &Certstream{
		URL: url,
		Log: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out := make(chan Cert, 8)
	go cs.Run(ctx, out)

	// Two certificates means two connections: the socket carries one each.
	for i := 0; i < 2; i++ {
		select {
		case <-out:
		case <-ctx.Done():
			t.Fatalf("only %d connection(s) before the deadline", conns())
		}
	}
	if got := conns(); got < 2 {
		t.Errorf("connections = %d, want at least 2", got)
	}
}

// The firehose has to dial through the resolver the monitor gives it. Left on
// the system resolver it reconnects through the very resolver a run probing
// hard has already starved — and reconnecting is the one thing a dropped
// firehose does a lot of.
func TestCertstreamDialsThroughTheSuppliedDialer(t *testing.T) {
	url := wsServer(t, sampleUpdate)

	var mu sync.Mutex
	var dialed []string
	cs := &Certstream{
		URL: url,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := make(chan Cert, 4)
	go cs.Run(ctx, out)

	select {
	case <-out:
	case <-ctx.Done():
		t.Fatal("no certificate arrived")
	}
	cancel()

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Error("certstream connected without using the dialer it was given")
	}
}

// silentWSServer accepts websocket connections, answers pings, and never says
// anything of its own. It is the public firehose as measured in August 2026: a
// handshake that succeeds and then no frames at all.
func silentWSServer(t *testing.T) (url string, conns func() int) {
	t.Helper()
	var (
		mu sync.Mutex
		n  int
	)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		mu.Lock()
		n++
		mu.Unlock()
		// Reading is what sends the pongs: gorilla answers a ping from
		// inside ReadMessage, so a server that never reads is silent in a
		// second way this test is not about.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// TestCertstreamDropsAFeedThatSaysNothing is the failure the run could not
// see. The firehose held a connection open for an entire measured run while
// sending no frames of any kind, and the deadline meant to catch that was
// reset by the pong handler on every keepalive the run itself sent — so the
// monitor's own liveness check kept a dead feed alive. Nothing is worth
// staying connected to a feed that is delivering nothing for, and the only
// place a socket that is technically fine can go is round again.
func TestCertstreamDropsAFeedThatSaysNothing(t *testing.T) {
	url, conns := silentWSServer(t)

	var lines lockedBuffer
	cs := &Certstream{
		URL:         url,
		IdleTimeout: 200 * time.Millisecond,
		Log:         slog.New(slog.NewTextHandler(&lines, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go cs.Run(ctx, make(chan Cert, 1))

	waitFor(t, "a silent firehose to be dropped and dialled again", func() bool {
		return conns() >= 2
	})
	if got := lines.String(); !strings.Contains(got, "sent nothing") {
		t.Errorf("the run reports a dropped socket rather than a quiet feed:\n%s", got)
	}
}

// TestCertstreamKeepsAConnectionThatIsStillTalking draws the line the deadline
// is actually on, which is frames and not certificates. A firehose sending
// heartbeats is a service that is up and has nothing to report, and dropping
// it every minute would reconnect its way to the same silence. Telling that
// apart from a feed that has quietly stopped carrying needs a count of
// certificates per feed, which the run does not keep yet.
func TestCertstreamKeepsAConnectionThatIsStillTalking(t *testing.T) {
	var (
		mu sync.Mutex
		n  int
	)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		mu.Lock()
		n++
		mu.Unlock()
		for {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(sampleHeartbeat)); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)

	cs := &Certstream{
		URL:         "ws" + strings.TrimPrefix(srv.URL, "http"),
		IdleTimeout: 300 * time.Millisecond,
		Log:         slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go cs.Run(ctx, make(chan Cert, 1))

	time.Sleep(1500 * time.Millisecond)
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if n != 1 {
		t.Errorf("dialled %d times over five idle timeouts of heartbeats, want once", n)
	}
}
