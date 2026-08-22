package source

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
