// Package probe fetches https://<host>/ and hashes the body.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// Result is one HTTPS fetch.
type Result struct {
	Status   int    // HTTP status of the final response
	FinalURL string // URL after redirects
	Size     int64  // bytes hashed, capped at MaxBody
	Hash     string // sha256 of the body, hex; empty when the fetch failed
	Err      error
}

// Prober fetches sites politely: bounded concurrency, a global rate limit,
// hard timeouts, and a cap on how much body it will read.
type Prober struct {
	client    *http.Client
	limiter   *rate.Limiter
	userAgent string
	maxBody   int64
}

// Options configure a Prober.
type Options struct {
	// Timeout bounds one probe end to end (default 10s).
	Timeout time.Duration
	// MaxBody caps how many bytes are read and hashed (default 2 MiB).
	// Bodies larger than this hash their first MaxBody bytes.
	MaxBody int64
	// RequestsPerSecond caps outbound probes across all workers (default 20).
	RequestsPerSecond float64
	// Burst is the rate limiter burst (default 5).
	Burst int
	// MaxRedirects is how many redirects to follow (default 3).
	MaxRedirects int
	// VerifyTLS validates certificates. It is off by default: the point is
	// to fingerprint whatever the host serves, and hosts found through CT
	// routinely serve mismatched or expired certificates.
	VerifyTLS bool
	// AllowPrivate permits probes of loopback, RFC 1918, link-local, and the
	// other addresses that are not out on the public internet. It is off by
	// default. Every hostname reaching this package came out of a stranger's
	// certificate, and anyone who can have one issued for a name that resolves
	// to 127.0.0.1 could otherwise point the monitor at services on the
	// machine running it and read the status, size, and body hash back out of
	// the store.
	AllowPrivate bool
	UserAgent    string
	// DialContext overrides how connections are made. Leave it nil for
	// normal use; it exists so tests can point every host at one server.
	// A dialer supplied here brings its own policy: AllowPrivate applies to
	// the built-in dialer, which is the only one that sees resolved
	// addresses before connecting.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New builds a Prober. The returned Prober is safe for concurrent use.
func New(opts Options) *Prober {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 2 << 20
	}
	if opts.RequestsPerSecond <= 0 {
		opts.RequestsPerSecond = 20
	}
	if opts.Burst <= 0 {
		opts.Burst = 5
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 3
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "ctmon/1.0"
	}

	dial := opts.DialContext
	if dial == nil {
		d := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 15 * time.Second,
		}
		if !opts.AllowPrivate {
			d.Control = refusePrivate
		}
		dial = d.DialContext
	}
	// Keepalives are off on purpose. A probe makes one request per host and
	// the hosts almost never repeat, so a pool would only hold thousands of
	// idle sockets open to sites we are done with. That also means there is no
	// connection to hand back, so nothing here drains a body it has finished
	// with: the transport closes the socket either way.
	tr := &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !opts.VerifyTLS},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: opts.Timeout,
		DisableKeepAlives:     true,
	}
	return &Prober{
		client: &http.Client{
			Transport: tr,
			Timeout:   opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= opts.MaxRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		limiter:   rate.NewLimiter(rate.Limit(opts.RequestsPerSecond), opts.Burst),
		userAgent: opts.UserAgent,
		maxBody:   opts.MaxBody,
	}
}

// Probe fetches https://host/ and returns the body hash. A failed fetch is
// reported in Result.Err, not as an error return: an unreachable host is a
// normal outcome worth recording.
func (p *Prober) Probe(ctx context.Context, host string) Result {
	if err := p.limiter.Wait(ctx); err != nil {
		return Result{Err: err}
	}

	url := "https://" + host + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Err: err}
	}
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := p.client.Do(req)
	if err != nil {
		// Do returns a *url.Error, which already reads
		// `Get "https://host/": <cause>`. Naming the URL again here only
		// printed it twice. When a redirect failed, the URL it carries is
		// the one that failed, which is worth more than the one we asked
		// for, so pass it through rather than restating either.
		return Result{Err: err}
	}
	defer resp.Body.Close()

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, p.maxBody))
	res := Result{
		Status:   resp.StatusCode,
		FinalURL: resp.Request.URL.String(),
		Size:     n,
		Hash:     hex.EncodeToString(h.Sum(nil)),
	}
	if err != nil {
		// Keep the partial hash out of the record: it is not reproducible.
		return Result{Status: res.Status, FinalURL: res.FinalURL, Err: fmt.Errorf("read body: %w", err)}
	}
	return res
}
