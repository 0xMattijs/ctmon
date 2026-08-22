package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dialTo sends every connection to addr, so a probe of any hostname reaches
// the test server.
func dialTo(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}

func TestProbeHashesBody(t *testing.T) {
	body := "<html><body>hello</body></html>"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	p := New(Options{DialContext: dialTo(srv.Listener.Addr().String())})
	res := p.Probe(context.Background(), "example.test")
	if res.Err != nil {
		t.Fatalf("probe failed: %v", res.Err)
	}
	if res.Status != 200 {
		t.Errorf("status = %d, want 200", res.Status)
	}
	if res.Size != int64(len(body)) {
		t.Errorf("size = %d, want %d", res.Size, len(body))
	}
	want := sha256.Sum256([]byte(body))
	if res.Hash != hex.EncodeToString(want[:]) {
		t.Errorf("hash = %s, want %s", res.Hash, hex.EncodeToString(want[:]))
	}
}

func TestProbeCapsBody(t *testing.T) {
	const cap = 1024
	big := strings.Repeat("a", 8192)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(big))
	}))
	defer srv.Close()

	p := New(Options{MaxBody: cap, DialContext: dialTo(srv.Listener.Addr().String())})
	res := p.Probe(context.Background(), "big.test")
	if res.Err != nil {
		t.Fatalf("probe failed: %v", res.Err)
	}
	if res.Size != cap {
		t.Fatalf("size = %d, want %d", res.Size, cap)
	}
	want := sha256.Sum256([]byte(big[:cap]))
	if res.Hash != hex.EncodeToString(want[:]) {
		t.Errorf("hash is not the hash of the first %d bytes", cap)
	}
}

func TestProbeRecordsFailure(t *testing.T) {
	p := New(Options{
		Timeout: 2 * time.Second,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("refused")}
		},
	})
	res := p.Probe(context.Background(), "down.test")
	if res.Err == nil {
		t.Fatal("want an error for an unreachable host")
	}
	if res.Hash != "" {
		t.Errorf("failed probe produced a hash: %s", res.Hash)
	}
}

func TestProbeFollowsRedirect(t *testing.T) {
	body := "final"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	p := New(Options{DialContext: dialTo(srv.Listener.Addr().String())})
	res := p.Probe(context.Background(), "redir.test")
	if res.Err != nil {
		t.Fatalf("probe failed: %v", res.Err)
	}
	if !strings.HasSuffix(res.FinalURL, "/final") {
		t.Errorf("final URL = %s, want .../final", res.FinalURL)
	}
	want := sha256.Sum256([]byte(body))
	if res.Hash != hex.EncodeToString(want[:]) {
		t.Errorf("hash is not the hash of the redirected body")
	}
}
