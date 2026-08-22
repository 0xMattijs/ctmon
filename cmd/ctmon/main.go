// Command ctmon watches Certificate Transparency logs for newly issued
// certificates, derives hostnames from each certificate's Common Name, and
// records every hostname together with a hash of the HTML it serves.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mvo/ct/internal/pipeline"
	"github.com/mvo/ct/internal/probe"
	"github.com/mvo/ct/internal/source"
	"github.com/mvo/ct/internal/store"
)

const usage = `ctmon — certificate transparency domain monitor

usage:
  ctmon run    [flags]        follow CT logs and record discovered domains
  ctmon list   [flags]        list stored domains
  ctmon get    <host>         show one domain record as JSON
  ctmon stats                 summarize the store
  ctmon migrate [flags]       rewrite an old JSON database into the packed format
  ctmon compact [flags]       repack the database into full pages

Run "ctmon <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "run":
		err = runCmd(args)
	case "list":
		err = listCmd(args)
	case "get":
		err = getCmd(args)
	case "stats":
		err = statsCmd(args)
	case "migrate":
		err = migrateCmd(args)
	case "compact":
		err = compactCmd(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		dbPath   = fs.String("db", "ct.db", "path to the bbolt database")
		sources  = fs.String("source", "both", "certificate feed: certstream, ctlog, or both")
		csURL    = fs.String("certstream-url", source.DefaultCertstreamURL, "certstream websocket URL")
		logURIs  = fs.String("logs", "", "comma-separated CT log URLs (default: discover usable logs)")
		listURL  = fs.String("log-list-url", "", "CT log list URL (default: Google's v3 list)")
		fromTop  = fs.Bool("from-start", false, "read each new log from index 0 instead of its current tip")
		batch    = fs.Int("batch", 256, "entries per get-entries request (a ceiling: a log that times out gets asked for less)")
		maxLag   = fs.Uint64("max-lag", 0, "skip a log to its tree head when it falls this many entries behind (0 = never skip)")
		poll     = fs.Duration("poll", 30*time.Second, "how long to wait after catching up with a log")
		logRPS   = fs.Float64("log-rps", 4, "get-entries requests per second, per log")
		workers  = fs.Int("workers", 16, "concurrent HTTPS probes")
		writers  = fs.Int("writers", 4, "concurrent store writers")
		backfill = fs.Duration("backfill", time.Minute, "how often to sweep for hosts still waiting on a probe (0 disables)")
		bfBatch  = fs.Int("backfill-batch", 5000, "maximum hosts queued per sweep")
		reprobe  = fs.Duration("reprobe", 0, "re-probe a known host after this long (0 disables)")
		skipSfx  = fs.String("skip-suffix", "", "extra parent domains to drop, comma-separated, e.g. workers.dev,pages.dev")
		skipFile = fs.String("skip-suffix-file", "", "file of extra parent domains to drop, one per line (# comments allowed)")
		defSkip  = fs.Bool("default-skip", true, "apply the built-in hosting-platform blocklist")
		parCap   = fs.Int("parent-cap", pipeline.DefaultParentCap, "maximum new hosts accepted per registrable domain per window (0 = no cap)")
		parWin   = fs.Duration("parent-window", pipeline.DefaultParentWindow, "window for --parent-cap")
		recent   = fs.Int("recent-hosts", pipeline.DefaultRecentHosts, "hostnames the in-memory duplicate filter remembers (0 = default)")
		maxDepth = fs.Int("max-depth", pipeline.DefaultMaxDepth, "drop hosts nested deeper than this below their registrable domain (0 = no limit)")
		useSANs  = fs.Bool("sans", true, "read hostnames from subject alternative names, not just the CN")
		maxSANs  = fs.Int("max-sans", 0, "maximum SANs to read from one certificate (0 = all)")
		noProbe  = fs.Bool("no-probe", false, "record domains without fetching them")
		probeRPS = fs.Float64("probe-rps", 20, "HTTPS probes per second across all workers")
		timeout  = fs.Duration("probe-timeout", 10*time.Second, "per-probe timeout")
		maxBody  = fs.Int64("max-body", 2<<20, "bytes of body to read and hash")
		verify   = fs.Bool("verify-tls", false, "verify TLS certificates when probing")
		private  = fs.Bool("allow-private", false, "probe hosts that resolve to loopback, RFC 1918, or other non-public addresses")
		ua       = fs.String("user-agent", "ctmon/1.0 (+domain discovery)", "User-Agent for probes and CT requests")
		compact  = fs.Duration("compact-every", 24*time.Hour, "rewrite the database into full pages this often (0 disables)")
		snapPath = fs.String("snapshot", "", "where SIGUSR1 writes a readable copy of the database (default: <db>.snap)")
		report   = fs.Duration("report", time.Minute, "how often to log counters (0 disables)")
		status   = fs.Bool("status", true, "on a terminal, redraw the counters in place instead of logging a line per report interval")
		domains  = fs.Bool("domains", false, "log every new domain, one line each")
		verbose  = fs.Bool("v", false, "debug logging")
	)
	fs.Parse(args)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	// The live counter line and debug logging fight over the terminal, so
	// -v keeps the plain scrolling output.
	var line *statusLine
	if *status && !*verbose && *report > 0 {
		line = newStatusLine(os.Stderr)
	}
	var out io.Writer = os.Stderr
	if line != nil {
		out = line
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: level}))

	skip, err := loadSkipSuffixes(*skipSfx, *skipFile, *defSkip)
	if err != nil {
		return err
	}
	log.Info("filters",
		"skip_suffixes", len(skip),
		"parent_cap", *parCap,
		"parent_window", *parWin,
		"max_depth", *maxDepth,
	)

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	feeds, err := buildSources(*sources, *csURL, *logURIs, *listURL, *fromTop,
		*batch, *maxLag, *poll, *logRPS, *ua, db, log)
	if err != nil {
		return err
	}

	pipe := &pipeline.Pipeline{
		Store: db,
		Prober: probe.New(probe.Options{
			Timeout:           *timeout,
			MaxBody:           *maxBody,
			RequestsPerSecond: *probeRPS,
			VerifyTLS:         *verify,
			AllowPrivate:      *private,
			UserAgent:         *ua,
		}),
		Log:           log,
		Workers:       *workers,
		Writers:       *writers,
		Skip:          skip,
		ParentCap:     *parCap,
		ParentWindow:  *parWin,
		MaxDepth:      *maxDepth,
		IgnoreSANs:    !*useSANs,
		MaxSANs:       *maxSANs,
		Reprobe:       *reprobe,
		Backfill:      *backfill,
		BackfillBatch: *bfBatch,
		NoProbe:       *noProbe,
		LogDomains:    *domains,
		RecentHosts:   *recent,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certs := make(chan source.Cert, 1024)

	// Feeds run until cancelled; the pipeline drains the channel until every
	// feed has stopped and the channel is closed.
	var feedWG sync.WaitGroup
	for _, f := range feeds {
		feedWG.Add(1)
		go func(f source.Source) {
			defer feedWG.Done()
			log.Info("source started", "source", f.Name())
			if err := f.Run(ctx, certs); err != nil && ctx.Err() == nil {
				log.Error("source stopped", "source", f.Name(), "err", err)
			}
		}(f)
	}
	go func() {
		feedWG.Wait()
		close(certs)
	}()

	if *compact > 0 {
		go compactLoop(ctx, *compact, db, log)
	}

	// A run holds an exclusive lock on the database, so ctmon stats and the
	// rest cannot open it. Snapshot on a signal gives them something to read
	// without stopping the collection.
	if sig, ok := snapshotSignal(); ok {
		dst := *snapPath
		if dst == "" {
			dst = *dbPath + ".snap"
		}
		go snapshotLoop(ctx, sig, db, dst, log)
		log.Info("snapshot on signal", "signal", sig, "path", dst)
	}

	switch {
	case line != nil:
		go statusLoop(ctx, statusInterval, pipe, line)
	case *report > 0:
		go reportLoop(ctx, *report, pipe, log)
	}

	pipe.Run(ctx, certs)
	if line != nil {
		line.Stop()
	}
	logStats(pipe, log, "final")
	return nil
}

// loadSkipSuffixes merges the built-in blocklist with the inline and file
// lists. A missing file is an error: silently skipping the blocklist you asked
// for is worse than failing to start.
func loadSkipSuffixes(inline, path string, useDefault bool) (pipeline.SuffixSet, error) {
	var entries []string
	if useDefault {
		entries = pipeline.DefaultSkipSuffixes()
	}
	entries = append(entries, pipeline.ParseSuffixList(inline)...)
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read skip list: %w", err)
		}
		entries = append(entries, pipeline.ParseSuffixList(string(raw))...)
	}
	return pipeline.NewSuffixSet(entries), nil
}

// buildSources turns the flags into the configured feeds.
func buildSources(sel, csURL, logURIs, listURL string, fromStart bool,
	batch int, maxLag uint64, poll time.Duration, logRPS float64, ua string,
	db *store.Store, log *slog.Logger) ([]source.Source, error) {

	want := map[string]bool{}
	for _, s := range strings.Split(sel, ",") {
		switch s = strings.TrimSpace(s); s {
		case "both":
			want["certstream"], want["ctlog"] = true, true
		case "certstream", "ctlog":
			want[s] = true
		case "":
		default:
			return nil, fmt.Errorf("unknown source %q", s)
		}
	}
	if len(want) == 0 {
		return nil, errors.New("no sources selected")
	}

	var feeds []source.Source
	if want["certstream"] {
		feeds = append(feeds, &source.Certstream{URL: csURL, UserAgent: ua, Log: log})
	}
	if want["ctlog"] {
		var uris []string
		for _, u := range strings.Split(logURIs, ",") {
			if u = strings.TrimSpace(u); u != "" {
				uris = append(uris, u)
			}
		}
		if len(uris) == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var err error
			uris, err = source.DiscoverLogs(ctx, &http.Client{Timeout: 30 * time.Second}, listURL)
			if err != nil {
				return nil, err
			}
			log.Info("discovered ct logs", "count", len(uris))
		}
		feeds = append(feeds, &source.CTLog{
			URIs:              uris,
			Positions:         db,
			FromStart:         fromStart,
			BatchSize:         batch,
			MaxLag:            maxLag,
			PollInterval:      poll,
			RequestsPerSecond: logRPS,
			UserAgent:         ua,
			Log:               log,
		})
	}
	return feeds, nil
}

// compactLoop rewrites the database into full pages on a schedule. bolt never
// shrinks a file and random inserts leave leaf pages about 70% full, so a
// store left alone drifts to roughly twice the size of the records in it.
//
// Writes pause for the rewrite, which is why this is a scheduled job and not
// something the store does as it goes.
func compactLoop(ctx context.Context, every time.Duration, db *store.Store, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			start := time.Now()
			res, err := db.Compact()
			if err != nil {
				log.Error("compaction failed", "err", err)
				continue
			}
			log.Info("compacted",
				"in_use", humanBytes(res.NewUsed),
				"reclaimed", humanBytes(res.OldUsed-res.NewUsed),
				"file", humanBytes(res.NewBytes),
				"took", time.Since(start).Round(time.Millisecond))
		}
	}
}

// snapshotLoop writes a consistent copy of the store every time sig arrives.
//
// The copy is what ctmon stats, list, and get read while a run is going: bolt
// hands the writer an exclusive lock on the file, so those commands cannot
// open the live database at all, not even read-only.
func snapshotLoop(ctx context.Context, sig os.Signal, db *store.Store, path string, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			start := time.Now()
			n, err := db.Snapshot(path)
			if err != nil {
				log.Error("snapshot failed", "path", path, "err", err)
				continue
			}
			log.Info("snapshot written", "path", path,
				"size", humanBytes(n), "took", time.Since(start).Round(time.Millisecond))
		}
	}
}

// statusInterval is how often the in-place counter line is redrawn. It is not
// a flag: the line costs nothing to redraw and replaces no scrollback.
const statusInterval = time.Second

// statusLoop keeps the in-place counter line current.
func statusLoop(ctx context.Context, every time.Duration, p *pipeline.Pipeline, line *statusLine) {
	t := time.NewTicker(every)
	defer t.Stop()
	line.Set(statusText(statsFields(p)))
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			line.Set(statusText(statsFields(p)))
		}
	}
}

func reportLoop(ctx context.Context, every time.Duration, p *pipeline.Pipeline, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			logStats(p, log, "progress")
		}
	}
}

func logStats(p *pipeline.Pipeline, log *slog.Logger, msg string) {
	log.Info(msg, statsFields(p)...)
}

// statsFields renders the counters as alternating keys and values, so the
// progress line, the live status line, and the final line all share a shape.
func statsFields(p *pipeline.Pipeline) []any {
	s := p.Stats()
	return []any{
		"certs", s.Certs.Load(),
		"names", s.Names.Load(),
		"skipped_cn", s.Skipped.Load(),
		"too_deep", s.TooDeep.Load(),
		"from_san", s.FromSAN.Load(),
		"sans_cut", s.SANsCut.Load(),
		"blocked", s.Blocked.Load(),
		"capped", s.Capped.Load(),
		"new", s.New.Load(),
		"repeat", s.Repeat.Load(),
		"dup", s.Dup.Load(),
		"probed", s.Probed.Load(),
		"probe_failed", s.Failed.Load(),
		"changed", s.Changed.Load(),
		"deferred", s.Deferred.Load(),
		"backfilled", s.Backfilled.Load(),
	}
}

func listCmd(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var (
		dbPath   = fs.String("db", "ct.db", "path to the bbolt database")
		asJSON   = fs.Bool("json", false, "print full records as JSON lines")
		onlyHash = fs.Bool("with-hash", false, "only hosts that returned a body")
		onlyWild = fs.Bool("wildcard", false, "only hosts derived from wildcard CNs")
		changed  = fs.Bool("changed", false, "only hosts whose body hash has changed")
		under    = fs.String("under", "", "only this domain and the hosts beneath it")
		since    = fs.Duration("since", 0, "only hosts first seen within this window")
		limit    = fs.Int("limit", 0, "stop after N records (0 = all)")
	)
	fs.Parse(args)

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	enc := json.NewEncoder(os.Stdout)
	n := 0
	stop := errors.New("limit reached")
	walk := db.ForEach
	if *under != "" {
		walk = func(fn func(*store.Record) error) error { return db.ForEachUnder(*under, fn) }
	}
	err = walk(func(r *store.Record) error {
		switch {
		case *onlyHash && r.BodyHash == "":
			return nil
		case *onlyWild && !r.FromWildcard:
			return nil
		case *changed && r.PrevHash == "":
			return nil
		case *since > 0 && time.Since(r.FirstSeen) > *since:
			return nil
		}
		if *asJSON {
			if err := enc.Encode(r); err != nil {
				return err
			}
		} else {
			hash := r.BodyHash
			if hash == "" {
				hash = "-"
			}
			fmt.Printf("%s\t%d\t%s\t%s\n", r.Host, r.HTTPStatus, hash, r.FirstSeen.Format(time.RFC3339))
		}
		n++
		if *limit > 0 && n >= *limit {
			return stop
		}
		return nil
	})
	if errors.Is(err, stop) {
		return nil
	}
	return err
}

func getCmd(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	dbPath := fs.String("db", "ct.db", "path to the bbolt database")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ctmon get [--db path] <host>")
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rec, err := db.Get(strings.ToLower(fs.Arg(0)))
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("%s: not found", fs.Arg(0))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rec)
}

// humanBytes renders a byte count for a person.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// printSizes reports a size change both ways: the pages actually used, and the
// file on disk. bolt grows its file in large steps and never shrinks it, so
// the file alone can hide a real win.
func printSizes(indent string, oldUsed, newUsed, oldFile, newFile int64, records int) {
	fmt.Printf("%sin use:  %s -> %s", indent, humanBytes(oldUsed), humanBytes(newUsed))
	if newUsed > 0 {
		fmt.Printf("  (%.1fx smaller)", float64(oldUsed)/float64(newUsed))
	}
	fmt.Println()
	fmt.Printf("%son disk: %s -> %s\n", indent, humanBytes(oldFile), humanBytes(newFile))
	if records > 0 && newUsed > 0 {
		fmt.Printf("%s%d B/record -> %d B/record\n", indent,
			oldUsed/int64(records), newUsed/int64(records))
	}
}

// migrateCmd rewrites a legacy database. It never modifies the original.
func migrateCmd(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	var (
		dbPath = fs.String("db", "ct.db", "path to the old database (read only)")
		out    = fs.String("out", "", "path to write (default: <db>.packed)")
	)
	fs.Parse(args)

	dst := *out
	if dst == "" {
		dst = *dbPath + ".packed"
	}

	start := time.Now()
	res, err := store.Migrate(*dbPath, dst)
	if err != nil {
		return err
	}

	fmt.Printf("migrated %d records and %d log positions in %s\n",
		res.Records, res.LogPos, time.Since(start).Round(time.Millisecond))
	if res.Skipped > 0 {
		fmt.Printf("skipped %d unreadable records\n", res.Skipped)
	}
	printSizes("  ", res.OldUsed, res.NewUsed, res.OldBytes, res.NewBytes, res.Records)
	fmt.Printf("\nThe original is untouched. To use the new file:\n  mv %s %s\n", dst, *dbPath)
	return nil
}

// compactCmd repacks the store. It never modifies the original.
func compactCmd(args []string) error {
	fs := flag.NewFlagSet("compact", flag.ExitOnError)
	var (
		dbPath = fs.String("db", "ct.db", "path to the database (read only)")
		out    = fs.String("out", "", "path to write (default: <db>.compact)")
	)
	fs.Parse(args)

	dst := *out
	if dst == "" {
		dst = *dbPath + ".compact"
	}

	start := time.Now()
	res, err := store.Compact(*dbPath, dst)
	if err != nil {
		return err
	}
	fmt.Printf("compacted in %s\n", time.Since(start).Round(time.Millisecond))
	printSizes("  ", res.OldUsed, res.NewUsed, res.OldBytes, res.NewBytes, 0)
	fmt.Printf("\nThe original is untouched. To use the new file:\n  mv %s %s\n", dst, *dbPath)
	return nil
}

func statsCmd(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	dbPath := fs.String("db", "ct.db", "path to the bbolt database")
	fs.Parse(args)

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	st, err := db.Stats()
	if err != nil {
		return err
	}
	fmt.Printf("domains:    %d\n", st.Domains)
	fmt.Printf("probed:     %d\n", st.Probed)
	fmt.Printf("with hash:  %d\n", st.WithHash)
	fmt.Printf("wildcards:  %d\n", st.Wildcards)
	fmt.Printf("errors:     %d\n", st.Errors)
	fmt.Printf("changed:    %d\n", st.Changed)
	fmt.Printf("\nfile size:  %s\n", humanBytes(st.Bytes))
	if st.Domains > 0 {
		fmt.Printf("per record: %d B\n", st.Bytes/int64(st.Domains))
	}
	fmt.Printf("interned:   %d sources, %d issuers, %d error shapes\n",
		st.Sources, st.Issuers, st.ErrorKind)
	if len(st.Logs) > 0 {
		fmt.Printf("\nct log positions:\n")
		for _, uri := range slices.Sorted(maps.Keys(st.Logs)) {
			fmt.Printf("  %-60s %d\n", uri, st.Logs[uri])
		}
	}
	return nil
}
