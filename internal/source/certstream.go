package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// DefaultCertstreamURL is the public Calidog firehose.
const DefaultCertstreamURL = "wss://certstream.calidog.io/"

// DefaultCertstreamIdle is how long a connection may go without a frame
// before it is treated as one that has stopped carrying. The feed aggregates
// every log there is, and a whole second without a certificate on it is
// already unusual, so a minute is generous by two orders of magnitude.
const DefaultCertstreamIdle = 60 * time.Second

// Certstream reads an aggregated CT firehose over a websocket. It is the
// quickest feed to get running, at the cost of depending on a third party.
type Certstream struct {
	URL       string
	UserAgent string
	// Dial overrides how the websocket connection is made. Like CTLog's, it
	// exists so the monitor can give its own feed the same resolver it gives
	// the probers: the socket drops and reconnects, and each reconnect
	// resolves the firehose again — through a system resolver that a run
	// probing hard enough has already starved.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// IdleTimeout is how long a connection may go without a frame before it
	// is dropped and made again. Zero means DefaultCertstreamIdle.
	IdleTimeout time.Duration
	Log         *slog.Logger
}

// idle is how long a connection may go without a frame.
func (c *Certstream) idle() time.Duration {
	if c.IdleTimeout <= 0 {
		return DefaultCertstreamIdle
	}
	return c.IdleTimeout
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
		carried, err := c.stream(ctx, url, out)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ran := time.Since(start)
		d := rt.after(scoreRun(ran, carried))
		c.Log.Warn("certstream disconnected", "err", err, "certs", carried,
			"ran", ran.Round(time.Second), "retry_in", d)
		if err := sleep(ctx, d); err != nil {
			return err
		}
	}
}

// stream holds one websocket connection open and forwards every certificate
// update on it. It returns as soon as the connection fails, along with how
// many certificates it carried before that — which is what tells a feed having
// a bad minute from one that never had anything to say.
func (c *Certstream) stream(ctx context.Context, url string, out chan<- Cert) (int, error) {
	hdr := http.Header{}
	if c.UserAgent != "" {
		hdr.Set("User-Agent", c.UserAgent)
	}
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 30 * time.Second
	if c.Dial != nil {
		dialer.NetDialContext = c.Dial
	}
	conn, _, err := dialer.DialContext(ctx, url, hdr)
	if err != nil {
		return 0, fmt.Errorf("dial %s: %w", url, err)
	}
	defer conn.Close()
	c.Log.Info("certstream connected", "url", url)

	idleTimeout := c.idle()
	conn.SetReadLimit(4 << 20)

	// Close the socket on cancellation so the blocking read below returns,
	// and ping while it is open so an idle middlebox does not take the
	// connection for an abandoned one. The pings are paced off the same
	// timeout they can no longer defend, which leaves the default run doing
	// what it always did: one every 30 seconds. The floor is there because
	// IdleTimeout is a field anyone can set and NewTicker panics on zero,
	// which is a strange way for a monitor to end.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(max(idleTimeout/2, time.Millisecond))
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

	carried := 0
	for {
		// The firehose is chatty, so silence means a feed that has stopped
		// carrying, and this deadline is what says so.
		//
		// Pongs deliberately do not move it. They used to: the handler reset
		// it on every one, and the keepalive above pings every half timeout,
		// so the run's own liveness check held the connection open for as
		// long as the far end kept answering. The public firehose did exactly
		// that for a whole measured run while sending nothing at all. A
		// socket that is well and a feed that is delivering are two different
		// claims, and only the second is worth staying connected for.
		//
		// It is armed here rather than after the read below, so that it times
		// how long the feed has kept this run waiting and not how long this
		// run took to deal with what it last sent. Those are the same number
		// until the pipeline blocks — the store falling behind parks send()
		// for as long as it takes — and a feed must not be dropped for the
		// store's backlog.
		//
		// Only what the feed sends as data moves it. A control frame does
		// not: gorilla answers a ping from inside ReadMessage without
		// returning, so a server keeping a connection alive with websocket
		// pings alone would be dropped here every timeout. The firehose sends
		// its heartbeats as JSON, so that is a contract to check if it ever
		// changes rather than a case this is written against.
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			// A deadline armed for one read expires for one reason, and the
			// reason is not the network. Say which it was, and say whether
			// this connection ever carried anything: a firehose that has
			// never delivered and one that has just gone quiet are different
			// things to go and look at, and neither should scroll past
			// wearing the words a dropped connection would have used.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if carried == 0 {
					return carried, fmt.Errorf("connected and sent nothing for %v", idleTimeout)
				}
				return carried, fmt.Errorf("went quiet for %v", idleTimeout)
			}
			return carried, fmt.Errorf("read: %w", err)
		}

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
			return carried, err
		}
		carried++
	}
}

// scoreRun is how long a finished connection counts as having lasted, for the
// purpose of deciding whether the next one waits.
//
// A connection that carried nothing did not last, whatever the clock says
// about it. retry.after puts the delay back to base after a run of healthyRun,
// which is a minute, and a connection ended by the idle timeout has by
// definition been up for that timeout — a minute, at the default. So an
// endpoint that accepts connections and says nothing forever scored every
// failure as a healthy run and was redialled at the base delay, once a minute,
// escalating never.
//
// It came out that way because two constants chosen for unrelated reasons
// happened to be equal, and IdleTimeout is now a field: set it to 30s and the
// ladder is climbed, set it to 90s and it is not, for no reason a reader of
// either line could see. What the backoff wants to know is whether the last
// connection was worth having, and the run knows that outright.
func scoreRun(ran time.Duration, carried int) time.Duration {
	if carried == 0 {
		return 0
	}
	return ran
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
