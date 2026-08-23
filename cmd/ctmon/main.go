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
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mvo/ct/internal/pipeline"
	"github.com/mvo/ct/internal/resolve"
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
	var cfg runConfig
	cfg.bind(fs)
	fs.Parse(args)

	log, line := cfg.logger()

	skip, err := loadSkipSuffixes(cfg.filter.skipSuffix, cfg.filter.skipFile, cfg.filter.useDefaults)
	if err != nil {
		return err
	}
	log.Info("filters",
		"skip_suffixes", len(skip),
		"parent_cap", cfg.filter.parentCap,
		"parent_window", cfg.filter.parentWin,
		"max_depth", cfg.filter.maxDepth,
	)

	db, err := store.Open(cfg.dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// One resolver, shared. The feed dials through it so that a run probing
	// hard enough to saturate DNS does not starve its own source of
	// certificates.
	//
	// The feed's dialer carries no address filter, unlike the prober's. That
	// guard exists because anyone can have a certificate issued for a name
	// pointing at 127.0.0.1 and would otherwise aim this monitor at its own
	// machine. A CT log URL came from --logs or from the log list, which is
	// the operator's own configuration: refusing a log on their own network
	// would break an ordinary setup to guard against themselves.
	resolver := cfg.newResolver()
	prober := cfg.newProber(resolver)
	feeds, err := buildSources(cfg.feed, cfg.userAgent, db, log, resolve.Dialer(resolver, nil, nil))
	if err != nil {
		return err
	}
	pipe := cfg.newPipeline(db, prober, log, skip)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Seeding comes after the signal handler is installed, not before: on a
	// store of a couple of million records it runs for the best part of a
	// minute, and until the handler exists a Ctrl-C during it kills the
	// process outright.
	if !cfg.prober.disabled {
		if err := seedPending(ctx, db, pipe, log); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}

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

	if cfg.compactEvery > 0 {
		go compactLoop(ctx, cfg.compactEvery, db, log)
	}

	// A run holds an exclusive lock on the database, so ctmon stats and the
	// rest cannot open it. Snapshot on a signal gives them something to read
	// without stopping the collection.
	if sig, ok := snapshotSignal(); ok {
		dst := cfg.snapshotPath()
		go snapshotLoop(ctx, sig, db, dst, log)
		log.Info("snapshot on signal", "signal", sig, "path", dst)
	}

	switch {
	case line != nil:
		go statusLoop(ctx, statusInterval, pipe, line)
	case cfg.output.report > 0:
		go reportLoop(ctx, cfg.output.report, pipe, log)
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

// buildSources turns the feed flags into the configured feeds.
func buildSources(cfg feedConfig, userAgent string, db *store.Store, log *slog.Logger,
	dial func(ctx context.Context, network, addr string) (net.Conn, error)) ([]source.Source, error) {

	want := map[string]bool{}
	for _, s := range strings.Split(cfg.sources, ",") {
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
		feeds = append(feeds, &source.Certstream{URL: cfg.certURL, UserAgent: userAgent, Log: log})
	}
	if want["ctlog"] {
		uris := splitList(cfg.logURIs)
		if len(uris) == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var err error
			hc := &http.Client{Timeout: 30 * time.Second}
			if dial != nil {
				hc.Transport = &http.Transport{DialContext: dial, ForceAttemptHTTP2: true}
			}
			uris, err = source.DiscoverLogs(ctx, hc, cfg.listURL)
			if err != nil {
				return nil, err
			}
			log.Info("discovered ct logs", "count", len(uris))
		}
		feeds = append(feeds, &source.CTLog{
			URIs:              uris,
			Positions:         db,
			FromStart:         cfg.fromStart,
			BatchSize:         cfg.batch,
			MaxLag:            cfg.maxLag,
			PollInterval:      cfg.poll,
			RequestsPerSecond: cfg.rps,
			UserAgent:         userAgent,
			DialContext:       dial,
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
			res, err := db.CompactInPlace()
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
	line.Set(statusText(p.Stats().Fields()))
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			line.Set(statusText(p.Stats().Fields()))
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
	log.Info(msg, p.Stats().Fields()...)
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

	return withStore(*dbPath, func(db *store.Store) error {
		enc := json.NewEncoder(os.Stdout)
		n := 0
		stop := errors.New("limit reached")
		walk := db.ForEach
		if *under != "" {
			walk = func(fn func(*store.Record) error) error { return db.ForEachUnder(*under, fn) }
		}
		err := walk(func(r *store.Record) error {
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
	})
}

func getCmd(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	dbPath := fs.String("db", "ct.db", "path to the bbolt database")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ctmon get [--db path] <host>")
	}

	return withStore(*dbPath, func(db *store.Store) error {
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
	})
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
	res, err := store.CompactTo(*dbPath, dst)
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

	return withStore(*dbPath, func(db *store.Store) error {
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
		fmt.Printf("queued:     %d\n", st.Pending)
		if !st.Oldest.IsZero() {
			fmt.Printf("waiting:    %s (oldest queued probe)\n", waited(st.Oldest))
		}
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
	})
}

// withStore opens the database, hands it to fn, and closes it again. The
// read-only commands all want exactly this and nothing more.
func withStore(path string, fn func(*store.Store) error) error {
	db, err := store.Open(path)
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(db)
}

// splitList reads a comma-separated flag into its entries, dropping the empty
// ones a trailing comma leaves behind.
func splitList(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// seedPending fills the pending queue from records it does not yet know about.
// It walks every record, which on a large store takes a while and is worth
// saying so.
func seedPending(ctx context.Context, db *store.Store, pipe *pipeline.Pipeline, log *slog.Logger) error {
	start := time.Now()
	var last time.Time
	queued, ran, err := db.SeedPending(
		seedGeneration(pipe.Reprobe),
		func(r *store.Record) (time.Time, bool) {
			if !r.Probed {
				// Due when it was found, so the backlog comes out oldest
				// first.
				return r.FirstSeen, true
			}
			if pipe.Reprobe <= 0 {
				return time.Time{}, false
			}
			// Without this a host already probed is in no queue at all, so
			// turning --reprobe on would never reach the records that were
			// there before it was turned on.
			return r.ProbedAt.Add(pipe.Reprobe), true
		},
		func(scanned, queued int) {
			if ctx.Err() != nil || time.Since(last) < 5*time.Second {
				return
			}
			last = time.Now()
			log.Info("filling the probe queue", "scanned", scanned, "queued", queued)
		},
	)
	if err != nil {
		return err
	}
	if ran && queued > 0 {
		log.Info("probe queue filled from existing records",
			"queued", queued, "took", time.Since(start).Round(time.Second))
	}
	return nil
}

// seedGeneration names the re-probe policy a seed was run for. Changing the
// policy changes which records belong in the queue, so it has to be seeded
// again; leaving it alone must not re-walk the store on every start.
func seedGeneration(reprobe time.Duration) string {
	return fmt.Sprintf("v1:reprobe=%s", reprobe)
}

// waited renders how long the oldest queued probe has been due. A backlog is
// normal; one whose oldest entry keeps getting older is probing that cannot
// keep up.
func waited(due time.Time) string {
	d := time.Since(due)
	if d < 0 {
		return "not due yet"
	}
	return d.Round(time.Second).String()
}
