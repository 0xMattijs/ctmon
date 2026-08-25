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
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
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
  ctmon run     [flags]       follow CT logs and record discovered domains
  ctmon list    [flags]       list stored domains
  ctmon get     <host>        show one domain record as JSON
  ctmon stats                 summarize the store
  ctmon prune   [flags]       delete stored domains a retention rule has aged out
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
	case "prune":
		err = pruneCmd(args)
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
	feedDial := resolve.Dialer(resolver, cfg.feed.dialer(), nil)
	feeds, err := buildSources(cfg.feed, cfg.userAgent, db, log, feedDial)
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
	//
	// It is skipped outright when nothing sweeps the queue. Seeding is a walk
	// of every record that writes a queue entry for each one that wants a
	// probe, and with no sweep to take them out again that is minutes of work
	// to grow the store by millions of entries nothing will ever read.
	if pipe.Queuing() {
		if err := seedPending(ctx, db, pipe, log); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	} else {
		// Everything this run records gets no queue entry, including the hosts
		// it could not probe on arrival. Mark the store so the next run that
		// does sweep seeds the queue and picks them up.
		if err := db.MarkUnqueued(); err != nil {
			return err
		}
		if !pipe.NoProbe {
			log.Info("backfill is off: hosts are probed as they arrive and none are queued")
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
		go statusLoop(ctx, statusInterval, pipe, feeds, line)
	case cfg.output.report > 0:
		go reportLoop(ctx, cfg.output.report, pipe, feeds, log)
	}
	// A feed that has stopped carrying is watched for on its own schedule.
	go source.WatchFeeds(ctx, source.QuietCheck(cfg.feed.poll), log, feeds,
		stalled(certs, pipe.Stats()))

	pipe.Run(ctx, certs)
	if line != nil {
		line.Stop()
	}
	logStats(pipe, feeds, log, "final")
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
		// "both" is a name for a fixed pair, and it keeps naming the pair it
		// always named even though the default no longer spells itself that
		// way. A run that types it gets what it got before; changing what a
		// word means underneath the people already saying it is worse than
		// leaving a word that no longer matches the default.
		case "both":
			want["certstream"], want["ctlog"] = true, true
		case "all":
			want["certstream"], want["ctlog"], want["tiled"] = true, true, true
		case "certstream", "ctlog", "tiled":
			want[s] = true
		case "":
		default:
			return nil, fmt.Errorf("unknown source %q", s)
		}
	}
	if len(want) == 0 {
		return nil, errors.New("no sources selected")
	}

	// One pass over the log list serves both log readers, so a run following
	// both kinds does not fetch it twice to start. The list is read now, and
	// again while the run continues: which logs are current changes underneath
	// a long run. Naming a set explicitly skips both, and an explicit set is
	// not second-guessed.
	var (
		found    source.LogSet
		discover func(context.Context) (source.LogSet, error)
	)
	if (want["ctlog"] && cfg.logURIs == "") || (want["tiled"] && cfg.tiledURIs == "") {
		// Clamped once, here, so the number logged is the number applied. An
		// operator who has to reason about coverage reads this line to learn
		// which shards the run decided to follow, and a line reporting a
		// window the filter did not use would send them looking in the wrong
		// place.
		lookahead := max(cfg.logLookahead, 0)
		discover = logDiscoverer(cfg.listURL, lookahead, dial)
		var err error
		if found, err = discover(context.Background()); err != nil {
			return nil, err
		}
		log.Info("discovered ct logs", "rfc6962", len(found.RFC6962),
			"tiled", len(found.Tiled), "lookahead", lookahead)
		if !want["tiled"] && len(found.Tiled) > 0 {
			// The blind spot, counted. Static CT is where new shards are being
			// stood up, so this number climbs on its own as operators move
			// shards across, and a run that never mentions it goes on looking
			// complete right up to the day the list has no RFC 6962 logs left
			// on it.
			log.Warn("static ct logs on the list are not being followed",
				"count", len(found.Tiled), "follow_them_with", "--source ...,tiled")
		}
		if cfg.logRefresh <= 0 {
			discover = nil
		}
	}

	var feeds []source.Source
	if want["certstream"] {
		feeds = append(feeds, &source.Certstream{
			URL: cfg.certURL, UserAgent: userAgent, Dial: dial, Log: log,
		})
	}
	if want["ctlog"] {
		logs, refresh := namedLogs(splitList(cfg.logURIs), "--logs", log), (func(context.Context) ([]source.Log, error))(nil)
		if len(logs) == 0 {
			if logs = found.RFC6962; len(logs) == 0 {
				return nil, errors.New("the log list has no usable RFC 6962 logs accepting certificates now")
			}
			refresh = eachRefresh(discover, func(s source.LogSet) []source.Log { return s.RFC6962 })
		}
		feeds = append(feeds, &source.CTLog{
			Logs:              logs,
			Positions:         db,
			FromStart:         cfg.fromStart,
			BatchSize:         cfg.batch,
			MaxLag:            cfg.maxLag,
			PollInterval:      cfg.poll,
			RequestsPerSecond: cfg.rps,
			UserAgent:         userAgent,
			DialContext:       dial,
			Discover:          refresh,
			RefreshInterval:   cfg.logRefresh,
			Log:               log,
		})
	}
	if want["tiled"] {
		logs, refresh := namedLogs(splitList(cfg.tiledURIs), "--tiled-logs", log), (func(context.Context) ([]source.Log, error))(nil)
		if len(logs) == 0 {
			if logs = found.Tiled; len(logs) == 0 {
				return nil, errors.New("the log list has no usable Static CT API logs accepting certificates now")
			}
			refresh = eachRefresh(discover, func(s source.LogSet) []source.Log { return s.Tiled })
		}
		feeds = append(feeds, &source.TiledLog{
			Logs:              logs,
			Positions:         db,
			FromStart:         cfg.fromStart,
			MaxLag:            cfg.maxLag,
			PollInterval:      cfg.poll,
			RequestsPerSecond: cfg.rps,
			UserAgent:         userAgent,
			DialContext:       dial,
			Discover:          refresh,
			RefreshInterval:   cfg.logRefresh,
			Log:               log,
		})
	}
	return feeds, nil
}

// eachRefresh narrows a whole-list discoverer to the logs one feed can read.
//
// The two feeds refresh on their own timers and so fetch the list once each,
// unlike the single pass at startup. That is two requests a day against a
// static JSON file, which is not worth a shared cache and the staleness
// question that would come with one.
func eachRefresh(discover func(context.Context) (source.LogSet, error),
	of func(source.LogSet) []source.Log) func(context.Context) ([]source.Log, error) {
	if discover == nil {
		return nil
	}
	return func(ctx context.Context) ([]source.Log, error) {
		set, err := discover(ctx)
		if err != nil {
			return nil, err
		}
		return of(set), nil
	}
}

// namedLogs turns the URIs of an explicitly named log set into logs, and says
// once that nothing they sign will be checked.
//
// A log on Chrome's list arrives with the key it signs with, and every head it
// serves is verified against that key. A log named on the command line arrives
// with a URL and nothing else, and there is nowhere to get a key from — the
// log's own /ct/v1/get-sth or /checkpoint would be the log vouching for
// itself. Refusing to follow it would take these flags away from anyone
// pointing this at a log that is not on the list, which is what they are for,
// so it is followed on the strength of HTTPS to its own name and the run says
// so at startup rather than leaving it to be inferred from a missing line.
func namedLogs(uris []string, flag string, log *slog.Logger) []source.Log {
	if len(uris) == 0 {
		return nil
	}
	logs := make([]source.Log, len(uris))
	for i, uri := range uris {
		logs[i] = source.Log{URI: uri}
	}
	log.Warn("logs named on the command line come with no key; their signatures are not checked",
		"flag", flag, "logs", len(logs))
	return logs
}

// logDiscoverer returns a function that reads the CT log list, over the same
// dialer the feed uses so the list is fetched through the run's own resolver.
// The client is built once and shared, so a refresh that follows another
// closely reuses the connection.
//
// IdleConnTimeout is set for the same reason http.DefaultTransport sets it,
// and matters more here: refreshes are a day apart, and a transport that
// never reaps an idle connection would offer that day-old socket to the next
// one. A NAT or proxy that dropped it in the meantime says nothing — the
// request goes into a dead connection, waits out the 30s timeout, and costs a
// refresh that is not tried again for another day.
func logDiscoverer(listURL string, lookahead time.Duration, dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(context.Context) (source.LogSet, error) {
	hc := &http.Client{Timeout: 30 * time.Second}
	if dial != nil {
		hc.Transport = &http.Transport{
			DialContext:       dial,
			ForceAttemptHTTP2: true,
			IdleConnTimeout:   90 * time.Second,
		}
	}
	return func(ctx context.Context) (source.LogSet, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return source.DiscoverLogs(ctx, hc, listURL, lookahead)
	}
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
func statusLoop(ctx context.Context, every time.Duration, p *pipeline.Pipeline, feeds []source.Source, line *statusLine) {
	t := time.NewTicker(every)
	defer t.Stop()
	line.Set(statusText(counters(p, feeds)))
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			line.Set(statusText(counters(p, feeds)))
		}
	}
}

func reportLoop(ctx context.Context, every time.Duration, p *pipeline.Pipeline, feeds []source.Source, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			logStats(p, feeds, log, "progress")
		}
	}
}

func logStats(p *pipeline.Pipeline, feeds []source.Source, log *slog.Logger, msg string) {
	log.Info(msg, counters(p, feeds)...)
}

// stalled reports whether the run has stopped reading what its feeds hand it,
// answering once per check and remembering the last answer.
//
// A full channel is not the test on its own, and measuring said so: the feeds
// outrun the pipeline on an ordinary busy run, so the buffer sits full for
// most of it and vetoing on that alone reports nothing, ever. What a blocked
// run looks like is the buffer full *and* the pipeline reading none of it
// between two checks — then every feed is parked inside a send, none of their
// counts can move, and their silence is the store's and not theirs. While the
// pipeline drains, a full buffer just means feeds are taking turns, and one
// whose count never comes up is one that has stopped.
func stalled(certs chan source.Cert, stats *pipeline.Stats) func() bool {
	last := int64(-1)
	return func() bool {
		n := stats.Certs.Load()
		stuck := len(certs) == cap(certs) && n == last
		last = n
		return stuck
	}
}

// counters is what the pipeline has done, followed by what each feed has
// carried towards it. The per-feed counts go last because they are the only
// fields whose names depend on how the run was configured, and a line is
// easier to read when the part that is always the same starts it.
//
// They are printed even when there is only one feed, where they say no more
// than certs does. A run is not always watched by whoever started it, and
// "which feed was this?" is not a question the rest of the line answers.
func counters(p *pipeline.Pipeline, feeds []source.Source) []any {
	fields := p.Stats().Fields()
	for _, f := range feeds {
		fields = append(fields, "from_"+f.Name(), f.Delivered())
	}
	return fields
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

// pruneCmd deletes stored records a retention rule has aged out.
//
// It is the one command that removes anything, and the only one whose mistakes
// cannot be undone: a hostname deleted here is gone until a certificate names
// it again, which for a name that stopped being renewed is never. So the
// default is to count. Nothing is deleted without --apply, and the counting
// pass is exactly the pass that would have done the deleting, so what it
// reports is what --apply would remove and not an estimate of it.
func pruneCmd(args []string) error {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	var (
		dbPath  = fs.String("db", "ct.db", "path to the bbolt database")
		under   = fs.String("under", "", "restrict to this domain and every host beneath it")
		apply   = fs.Bool("apply", false, "actually delete; without it prune only counts")
		compact = fs.Bool("compact", false, "repack the database in place afterwards, to give the freed pages back to the disk")
	)
	var unseen, failed days
	fs.Var(&unseen, "unseen-for", "hosts no certificate has named in this long, e.g. 90d")
	fs.Var(&failed, "failed-since", "hosts probed, never answered, and first seen this long ago, e.g. 30d")
	fs.Parse(args)

	opts, err := pruneOptions(*under, time.Duration(unseen), time.Duration(failed))
	if err != nil {
		return err
	}
	opts.DryRun = !*apply

	db, err := openForPrune(*dbPath, *apply)
	if err != nil {
		return err
	}
	defer db.Close()

	start := time.Now()
	res, err := db.Prune(opts)
	took := time.Since(start).Round(time.Millisecond)
	if err != nil {
		// The record walk commits as it goes, so a failure in the queue pass
		// that follows it arrives with records already deleted. Saying only
		// what went wrong would leave an operator not knowing that.
		if res.Deleted > 0 {
			fmt.Printf("deleted %d of %d records in %s before failing\n",
				res.Deleted, res.Scanned, took)
		}
		return err
	}

	if opts.DryRun {
		fmt.Printf("%d of %d records match, and their queue entries with them (%s)\n",
			res.Deleted, res.Scanned, took)
		if res.Deleted > 0 {
			fmt.Printf("\nNothing was deleted. Add --apply to remove them.\n")
		}
		return nil
	}

	fmt.Printf("deleted %d of %d records and %d queue entries in %s\n",
		res.Deleted, res.Scanned, res.Pending, took)

	// The dictionaries are the third thing a deletion leaves behind, and they
	// are swept on every applying prune rather than only one that deleted
	// something — the same reasoning as the queue pass, and the same trap.
	// Gating on res.Deleted would mean a prune interrupted before this point
	// left entries that the re-run could never reach, because by then there
	// are no records left for it to delete.
	//
	// A failure here does not fail the command. The records and the queue
	// entries are already gone and correct; the dictionaries are bookkeeping
	// on top of that, and losing the --compact an operator asked for over a
	// bookkeeping error would be the worse trade.
	switch sweep, err := db.SweepDicts(); {
	case err != nil:
		fmt.Fprintln(os.Stderr, "warning: could not sweep the dictionaries:", err)
	case sweep.Total() > 0:
		fmt.Printf("forgot %d interned values no record still uses (%s): %d sources, %d issuers, %d error shapes\n",
			sweep.Total(), humanBytes(sweep.Bytes), sweep.Sources, sweep.Issuers, sweep.Errors)
	}

	// Queue entries count toward whether anything was freed. Re-running an
	// interrupted prune is the case: the records went the first time, so this
	// run deletes none of them and drops the entries the first one orphaned.
	if res.Deleted == 0 && res.Pending == 0 {
		return nil
	}
	if !*compact {
		// Deleting frees pages without shrinking the file, so a prune that
		// stops here has reclaimed nothing an operator can see.
		fmt.Printf("\nThe freed pages are still in the file. To give them back:\n"+
			"  ctmon compact --db %s      writes a repacked copy to %s.compact\n"+
			"or add --compact to the prune next time, which repacks in place.\n",
			*dbPath, *dbPath)
		return nil
	}
	cres, err := db.CompactInPlace()
	if err != nil {
		return err
	}
	fmt.Println("compacted:")
	printSizes(os.Stdout, "  ", cres.OldUsed, cres.NewUsed, cres.OldBytes, cres.NewBytes, 0)
	return nil
}

// openForPrune opens the database the way this run needs it.
//
// A counting run writes nothing, so it takes a handle that cannot write. That
// is not only tidiness: it is what lets prune answer a question about a
// snapshot. While a run holds the live database the snapshot is the only
// readable copy an operator has, and "how many records would this rule
// remove?" is exactly the question they can usefully ask of it. Only the
// deleting run has to refuse one, because only its work would be thrown away
// by the next SIGUSR1.
func openForPrune(path string, apply bool) (*store.Store, error) {
	if err := refuseMissing(path); err != nil {
		return nil, err
	}
	if !apply {
		db, err := store.OpenReadOnly(path)
		if err != nil {
			return nil, readErr(path, err)
		}
		return db, nil
	}
	if err := refuseSnapshot(path); err != nil {
		return nil, err
	}
	db, err := store.Open(path)
	if err != nil {
		if errors.Is(err, store.ErrLocked) {
			// Not the advice readErr gives. A snapshot is no use to a run that
			// deletes: writing to the copy leaves the database it was copied
			// from exactly as it was.
			return nil, fmt.Errorf("%w; prune writes to the database, so stop the run first", err)
		}
		return nil, err
	}
	return db, nil
}

// pruneOptions turns the retention flags into a scope and a predicate.
//
// Filters combine with and, not or. Given both --unseen-for and
// --failed-since, a record has to satisfy the two of them to go. That is the
// conservative reading of a pair of rules, and it is the one to take when
// guessing wrong deletes hostnames.
//
// At least one filter is required. "ctmon prune --apply" with no rule at all
// would empty the store, and there is no plausible way to type that on
// purpose — the command for starting over is deleting the file.
func pruneOptions(under string, unseen, failed time.Duration) (store.PruneOptions, error) {
	now := time.Now().UTC()
	var match []func(*store.Record) bool
	if unseen > 0 {
		match = append(match, store.Unseen(now.Add(-unseen)))
	}
	if failed > 0 {
		match = append(match, store.Failed(now.Add(-failed)))
	}
	if under == "" && len(match) == 0 {
		return store.PruneOptions{}, errors.New("prune needs a rule: --under, --unseen-for, or --failed-since")
	}
	return store.PruneOptions{Under: under, Match: store.All(match...)}, nil
}

// refuseSnapshot turns away a path that names a snapshot rather than a
// database.
//
// Reading a store while a run holds it means signalling for a snapshot and
// reading the copy, so a snapshot path is what an operator has in hand and in
// their shell history. Pruning it does nothing they want: the deletions land
// in a file the next SIGUSR1 overwrites, and the database they were trying to
// shrink is untouched. That is a failure with no symptom, which is worse than
// one with a message.
func refuseSnapshot(path string) error {
	if !strings.HasSuffix(path, snapshotSuffix) {
		return nil
	}
	instead := "the database it was copied from"
	if live := strings.TrimSuffix(path, snapshotSuffix); live != "" {
		instead = live
	}
	return fmt.Errorf("%s is a snapshot, and pruning it would change nothing:"+
		" the next snapshot overwrites it from the live database."+
		" Stop the run and prune %s instead", path, instead)
}

// refuseMissing turns away a path that names no database, the way the reading
// commands do.
//
// store.Open creates one, which is right for a run starting fresh and wrong
// here. A mistyped --db would otherwise conjure an empty store and report that
// nothing matched — a typo that reads as an answer, and the one kind of answer
// this command must never give by accident.
func refuseMissing(path string) error {
	switch fi, err := os.Stat(path); {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: %w", path, store.ErrNoDatabase)
	case err != nil:
		return err
	case fi.IsDir() || fi.Size() == 0:
		// The same check OpenReadOnly makes, for the same reason. An empty
		// file is what a mistyped shell redirect leaves behind, and store.Open
		// would happily initialize it into a fresh database and then report
		// that nothing matched.
		return fmt.Errorf("%s: %w", path, store.ErrNoDatabase)
	}
	return nil
}

// days is a duration flag that also understands days, because retention is
// something people count in days and 90d beats 2160h for saying so. Everything
// time.ParseDuration accepts still works, and a day count may carry a
// remainder: 90d, 36h, 1d12h.
//
// It is only on prune. The run's durations are timeouts and intervals, which
// nobody writes in days, and a flag type that shows up on half the commands is
// worse than one that shows up where it earns its place.
//
// Zero and negative windows are refused rather than parsed. Both name a rule
// that cannot be meant — "delete what no certificate has named in the last
// -30 days" is not a retention policy — and the layer above reads an unset
// window as "no rule given", so a window that arrived and then vanished would
// be silently dropped and leave whatever other rules were typed to delete
// strictly more than the operator asked for.
type days time.Duration

func (d *days) String() string {
	if d == nil || *d == 0 {
		return "0s"
	}
	if n := time.Duration(*d); n%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", n/(24*time.Hour))
	}
	return time.Duration(*d).String()
}

// maxDays bounds the day count, and the bound is about overflow rather than
// taste. A duration is int64 nanoseconds, so 106,752 days is the most that
// fits; past that the multiplication wraps silently, and a wrapped retention
// window is not a window that matches nothing — it is one whose cutoff lands
// in the future and matches every record in the store. On a command that
// deletes, that is the difference between a typo and an empty database.
//
// The bound is set well below the point where it could happen, because a
// retention rule of 274 years is a typo whatever the arithmetic does with it.
const maxDays = 100000

func (d *days) Set(s string) error {
	if s == "" {
		return errors.New("empty duration")
	}
	// time.ParseDuration has no unit spelled with a d, so the first one can
	// only be the day count this type adds.
	rest, n := s, time.Duration(0)
	if i := strings.IndexByte(s, 'd'); i >= 0 {
		count, err := strconv.Atoi(s[:i])
		if err != nil {
			return fmt.Errorf("invalid duration %q: want a whole number of days, like 90d", s)
		}
		if count > maxDays || count < -maxDays {
			return fmt.Errorf("invalid duration %q: %d days is not a retention rule", s, count)
		}
		n, rest = time.Duration(count)*24*time.Hour, s[i+1:]
	}
	if rest != "" {
		extra, err := time.ParseDuration(rest)
		if err != nil {
			return fmt.Errorf("invalid duration %q", s)
		}
		// time.ParseDuration bounds extra on its own, but the sum of two
		// durations that each fit need not.
		sum := n + extra
		if (extra > 0 && sum < n) || (extra < 0 && sum > n) {
			return fmt.Errorf("invalid duration %q: out of range", s)
		}
		n = sum
	}
	if n <= 0 {
		return fmt.Errorf("invalid duration %q: a retention window has to be positive", s)
	}
	*d = days(n)
	return nil
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
func printSizes(w io.Writer, indent string, oldUsed, newUsed, oldFile, newFile int64, records int) {
	fmt.Fprintf(w, "%sin use:  %s -> %s", indent, humanBytes(oldUsed), humanBytes(newUsed))
	if newUsed > 0 {
		fmt.Fprintf(w, "  (%.1fx smaller)", float64(oldUsed)/float64(newUsed))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%son disk: %s -> %s\n", indent, humanBytes(oldFile), humanBytes(newFile))
	if records > 0 && newUsed > 0 {
		fmt.Fprintf(w, "%s%d B/record -> %d B/record\n", indent,
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
	printSizes(os.Stdout, "  ", res.OldUsed, res.NewUsed, res.OldBytes, res.NewBytes, res.Records)
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
	printSizes(os.Stdout, "  ", res.OldUsed, res.NewUsed, res.OldBytes, res.NewBytes, 0)
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
		fmt.Printf("in use:     %s\n", humanBytes(st.Used))
		if st.Domains > 0 {
			fmt.Printf("per record: %d B\n", st.Used/int64(st.Domains))
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

// withStore opens the database for reading, hands it to fn, and closes it
// again. The read-only commands all want exactly this and nothing more.
//
// Reading is the whole contract: a path that names no database is an error
// rather than an invitation to create one, and the handle takes no write lock
// on the way past.
func withStore(path string, fn func(*store.Store) error) error {
	db, err := store.OpenReadOnly(path)
	if err != nil {
		return readErr(path, err)
	}
	defer db.Close()
	return fn(db)
}

// readErr says what to do about a database a run is holding. The store only
// reports that someone has it; the way in is a snapshot, and whether one can
// be asked for is a property of this build.
func readErr(path string, err error) error {
	if !errors.Is(err, store.ErrLocked) {
		return err
	}
	if _, ok := snapshotSignal(); ok {
		return fmt.Errorf("%w; send it %s and read the snapshot instead", err, snapshotSignalName)
	}
	return fmt.Errorf("%w; stop the run to read it", err)
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
	// Worth saying which of the two reasons a walk is happening for: an
	// unchanged --reprobe on an already seeded store otherwise says nothing.
	unqueued, err := db.Unqueued()
	if err != nil {
		return err
	}
	if unqueued {
		log.Info("a previous run recorded hosts without queuing them: filling the queue again")
	}
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
// again; leaving it alone must not re-walk the store on every start. A run
// with the sweep off leaves records the queue never learned about whatever the
// policy was, and says so with a marker of its own rather than through this.
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
