package source

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// DefaultCertstreamURL is the public Calidog firehose.
const DefaultCertstreamURL = "wss://certstream.calidog.io/"

// Certstream reads an aggregated CT firehose over a websocket. It is the
// quickest feed to get running, at the cost of depending on a third party.
type Certstream struct {
	URL       string
	UserAgent string
	Log       *slog.Logger
}

// Name implements Source.
func (c *Certstream) Name() string { return "certstream" }

// certstreamMsg is the subset of the firehose message we read.
type certstreamMsg struct {
	MessageType string `json:"message_type"`
	Data        struct {
		LeafCert struct {
			Subject struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Issuer struct {
				CN string `json:"CN"`
				O  string `json:"O"`
			} `json:"issuer"`
			NotBefore float64 `json:"not_before"`
			NotAfter  float64 `json:"not_after"`
			// AllDomains is the CN plus every dNSName SAN.
			AllDomains []string `json:"all_domains"`
		} `json:"leaf_cert"`
		Source struct {
			Name string `json:"name"`
		} `json:"source"`
		Seen float64 `json:"seen"`
	} `json:"data"`
}

// Run streams certificates until ctx is cancelled, reconnecting with
// exponential backoff whenever the socket drops.
func (c *Certstream) Run(ctx context.Context, out chan<- Cert) error {
	url := c.URL
	if url == "" {
		url = DefaultCertstreamURL
	}
	rt := retry{base: time.Second, max: 2 * time.Minute}
	for {
		start := time.Now()
		err := c.stream(ctx, url, out)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ran := time.Since(start)
		d := rt.after(ran)
		c.Log.Warn("certstream disconnected", "err", err,
			"ran", ran.Round(time.Second), "retry_in", d)
		if err := sleep(ctx, d); err != nil {
			return err
		}
	}
}

// stream holds one websocket connection open and forwards every certificate
// update on it. It returns as soon as the connection fails.
func (c *Certstream) stream(ctx context.Context, url string, out chan<- Cert) error {
	hdr := http.Header{}
	if c.UserAgent != "" {
		hdr.Set("User-Agent", c.UserAgent)
	}
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 30 * time.Second
	conn, _, err := dialer.DialContext(ctx, url, hdr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", url, err)
	}
	defer conn.Close()
	c.Log.Info("certstream connected", "url", url)

	// The firehose is chatty, so silence for a minute means a dead socket.
	const idleTimeout = 60 * time.Second
	conn.SetReadLimit(4 << 20)
	conn.SetReadDeadline(time.Now().Add(idleTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(idleTimeout))
	})

	// Close the socket on cancellation so the blocking read below returns.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				conn.Close()
				return
			case <-done:
				return
			case <-ticker.C:
				_ = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
			}
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		var msg certstreamMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			c.Log.Debug("certstream: bad message", "err", err)
			continue
		}
		if msg.MessageType != "certificate_update" {
			continue // heartbeats
		}
		leaf := msg.Data.LeafCert
		if leaf.Subject.CN == "" && len(leaf.AllDomains) == 0 {
			continue
		}
		issuer := leaf.Issuer.CN
		if issuer == "" {
			issuer = leaf.Issuer.O
		}
		cert := Cert{
			CN:        leaf.Subject.CN,
			SANs:      leaf.AllDomains,
			Issuer:    issuer,
			NotBefore: unix(leaf.NotBefore),
			NotAfter:  unix(leaf.NotAfter),
			SeenAt:    time.Now().UTC(),
			Source:    "certstream",
			Index:     -1,
		}
		if err := send(ctx, out, cert); err != nil {
			return err
		}
	}
}

// unix converts a certstream timestamp (unix seconds, possibly fractional or
// absent) to a time.
func unix(f float64) time.Time {
	if f <= 0 {
		return time.Time{}
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC()
}
