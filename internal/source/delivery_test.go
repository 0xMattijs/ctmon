package source

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestDeliveryCountsWhatTheChannelTook is the counter on its own. A
// certificate the pipeline never received is not one this feed carried, so a
// cancelled send must leave the count where it was.
func TestDeliveryCountsWhatTheChannelTook(t *testing.T) {
	var d delivery
	if n := d.Delivered(); n != 0 {
		t.Fatalf("a feed that has run nothing reports %d delivered", n)
	}

	out := make(chan Cert, 2)
	for i := 0; i < 2; i++ {
		if err := d.send(context.Background(), out, Cert{}); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if n := d.Delivered(); n != 2 {
		t.Errorf("delivered = %d after two sends, want 2", n)
	}

	// The channel is full and the context is done, which is the shutdown
	// path: Run returns and the certificate is dropped.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.send(ctx, out, Cert{}); err == nil {
		t.Fatal("send on a cancelled context returned no error")
	}
	if n := d.Delivered(); n != 2 {
		t.Errorf("delivered = %d after a dropped send, want 2", n)
	}
}

// TestTiledCountsWhatItDelivered is the counter where the run reads it: what a
// feed says it carried against what actually arrived.
func TestTiledCountsWhatItDelivered(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 300)}
	feed := tiledOf(log.serve(t), newPositions())
	feed.FromStart = true
	got := runTiled(t, feed)

	waitFor(t, "the whole log to be read", func() bool { return got.len() == 300 })
	if n := feed.Delivered(); n != 300 {
		t.Errorf("the feed reports %d delivered, and 300 arrived", n)
	}
}

// TestCertstreamCountsWhatItDelivered is the same for the feed the count was
// wanted for, where a heartbeat and a certificate look alike from outside:
// only the certificate counts.
func TestCertstreamCountsWhatItDelivered(t *testing.T) {
	url := wsServer(t, sampleHeartbeat, sampleUpdate)
	cs := &Certstream{
		URL: url,
		Log: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan Cert, 4)
	go cs.Run(ctx, out)

	select {
	case <-out:
	case <-ctx.Done():
		t.Fatal("no certificate arrived before the deadline")
	}
	waitFor(t, "the feed to count what it sent", func() bool { return cs.Delivered() == 1 })
}
