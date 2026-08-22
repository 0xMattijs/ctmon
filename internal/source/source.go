// Package source provides certificate feeds. Each implementation streams
// newly logged certificates from somewhere and emits them on a channel.
package source

import (
	"context"
	"time"
)

// Cert is one observed certificate, reduced to the fields the monitor needs.
type Cert struct {
	// CN is the Subject Common Name, verbatim from the certificate. It is
	// empty for the many certificates that carry names only in SANs.
	CN string
	// SANs are the dNSName subject alternative names, verbatim. Modern
	// certificates put every name they cover here, so this is usually the
	// larger and more complete list.
	SANs []string
	// Issuer names the CA, for context in the stored record.
	Issuer string
	// NotBefore and NotAfter are the certificate's validity window.
	NotBefore time.Time
	NotAfter  time.Time
	// SeenAt is when this monitor observed the certificate.
	SeenAt time.Time
	// Source identifies the feed: "certstream" or a CT log URI.
	Source string
	// Index is the leaf index in the log, or -1 when the feed does not
	// report one.
	Index int64
}

// Source is a certificate feed.
//
// Run streams certificates to out until ctx is cancelled, and returns
// ctx.Err() on a clean shutdown. A Source is responsible for its own
// reconnects and backoff: returning a non-nil error means the feed has failed
// in a way retrying will not fix.
type Source interface {
	// Name identifies the source in logs.
	Name() string
	Run(ctx context.Context, out chan<- Cert) error
}

// send delivers c to out unless ctx is cancelled first.
func send(ctx context.Context, out chan<- Cert, c Cert) error {
	select {
	case out <- c:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// backoff returns the delay before retry number n (0-based), capped at max.
func backoff(n int, base, max time.Duration) time.Duration {
	d := base
	for i := 0; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// healthyRun is how long a feed has to stay up before its failure counts as a
// fresh one. Without it the backoff only ever climbs: a feed that drops once an
// hour would end up waiting the maximum between every retry, forever.
const healthyRun = time.Minute

// retry paces reconnection to a feed that keeps failing. The delay doubles
// from base to max, and a run that lasted healthyRun puts it back to base.
//
// Both feeds share this rather than each writing the loop, because the order
// of the two steps is easy to get wrong and invisible when you do: reset the
// counter after reading the delay and the healthy run still pays the long
// pause it was supposed to have earned its way out of.
type retry struct {
	base    time.Duration
	max     time.Duration
	attempt int
}

// after folds one finished run into the counter and returns how long to wait
// before trying again. ran is how long that run lasted.
func (r *retry) after(ran time.Duration) time.Duration {
	if ran >= healthyRun {
		r.attempt = 0
	}
	d := backoff(r.attempt, r.base, r.max)
	r.attempt++
	return d
}

// sleep waits for d, or until ctx is cancelled.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
