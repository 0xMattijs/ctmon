# ctmon — a certificate transparency domain monitor

`ctmon` watches Certificate Transparency logs for newly issued certificates,
derives hostnames from each certificate's Common Name and subject alternative
names, and records every hostname together with a SHA-256 hash of the HTML it
serves over HTTPS.

```console
$ ctmon run --db ct.db
INFO discovered ct logs count=9
INFO certstream connected url=wss://certstream.calidog.io/
certs=26470 names=47845 skipped_cn=1204 too_deep=9331 from_san=21285 ...
```

## While it runs

The last line is a counter line, rewritten in place once a second. It carries
the same counters as the summary printed on exit, so nothing you watch during
the run changes shape when it ends. Notable events — a feed reconnecting, a
body hash changing, a write failing — scroll above it.

`ctmon` does not print a line per domain: at a few hundred certificates a
second the names arrive faster than anyone can read them, and the counters say
more. To see them anyway:

| Flag | Effect |
|---|---|
| `--domains` | log every newly stored hostname, one line each |
| `--status=false` | log a counter line per `--report` interval instead of redrawing one |
| `--report 30s` | how often counters are logged when the line is off (0 disables both) |
| `-v` | debug logging, including every probe; turns the counter line off |
| `--compact-every` | how often to rewrite the database into full pages (default 24h) |

The counter line needs a terminal. Redirect the output to a file or a log
collector and `ctmon` falls back to a logged line per `--report` interval, so
nothing writes control characters into your logs.

## What it stores

One record per hostname, keyed by the hostname. Names come from the Common
Name and from the dNSName SANs, deduplicated per certificate:

| Name in the certificate | Hostnames stored |
|---|---|
| `shop.example.com` | `shop.example.com` |
| `*.example.com` | `example.com`, `www.example.com` |
| `*.www.example.com` | `www.example.com` |

A wildcard yields the apex it covers plus the `www` host under it, because
those are the two names a wildcard almost always serves. Names that are not
hostnames — CA names, email addresses, IP addresses — are skipped.

Reading SANs roughly triples the yield: in a one-minute live sample, 26,470
certificates produced 47,845 names, 21,285 of them from SANs alone. It also
catches the many certificates that carry no CN at all. Each record notes which
field it came from in `origin`, so you can tell a direct claim from a
name that merely rode along in a SAN list. Turn SANs off with `--sans=false`,
or bound packed certificates with `--max-sans N`.

## Limiting subdomain depth

CT is full of deeply nested machine-generated names, so `ctmon` keeps only
hosts within one label of their registrable domain by default. This is the
first of three noise filters, all on by default. `--max-depth N` sets the
limit; `--max-depth 0` turns it off and keeps everything.

```console
$ ctmon run --db ct.db                  # the default: --max-depth 1
$ ctmon run --db ct.db --max-depth 2    # allow one more level
$ ctmon run --db ct.db --max-depth 0    # no limit
```

| Host | Depth | Kept at the default |
|---|---|---|
| `example.com` | 0 | yes |
| `www.example.com` | 1 | yes |
| `www.example.co.uk` | 1 | yes |
| `deep.sub.example.com` | 2 | no |
| `a.b.c.example.com` | 3 | no |

Depth counts nesting, not dots. It comes from the public suffix list, so
`example.com.br` is depth 0 and `rekimin-arc.city.toon.ehime.jp` is depth 1 —
five labels, but `city.toon.ehime.jp` is a suffix. A wildcard is filtered per
resulting host: with `--max-depth 1`, `*.sub.example.com` stores the apex
`sub.example.com` and drops `www.sub.example.com`.

On a live sample the default dropped 18% of names (2,928 of 16,239 in a
minute). Raise or disable the limit if you are hunting for the deep names
themselves — staging and per-tenant hosts often live there.

Regardless of the setting, a host that is itself a public suffix is never
stored: `*.co.uk` yields `www.co.uk`, not `co.uk`, because nobody owns `co.uk`.

Depth does not catch every kind of noise. Random-label hosts under a shared
parent — `03c38136e4db4dfa98809ea981f19814.plex.direct` — are depth 1 and
structurally identical to a real discovery. The next two filters exist for
them.

## Muting hosting platforms

A blocklist entry drops every host at or under a parent domain, which mutes a
whole platform with one line. `ctmon` ships with one and applies it by
default: `internal/pipeline/skiplist.txt`, compiled into the binary, holding
the 17 platforms seen flooding a live sample — Workers, Pages, Vercel,
Zendesk, Synology QuickConnect and friends.

It is a starting point, not a maintained list. Add to it, or drop it:

```console
$ ctmon run --db ct.db --skip-suffix crm.dev,azure-api.net
$ ctmon run --db ct.db --skip-suffix-file my-platforms.txt
$ ctmon run --db ct.db --default-skip=false          # built-in list off
```

The built-in list and both flags combine. Files take `#` comments and accept
one entry per line or comma-separated, and a missing file is a startup error
rather than a silently empty blocklist.

## Capping runaway parents

A blocklist only mutes platforms you already know. The parent cap bounds the
rest: at most N *new* hosts per registrable domain per window. It defaults to
**20 per 10 minutes**.

```console
$ ctmon run --db ct.db --parent-cap 50 --parent-window 1h
$ ctmon run --db ct.db --parent-cap 0                  # cap off
```

Two things are exempt. The registrable domain itself is never capped — it is
the one name under a parent that is never noise. And hosts already in the
store are never capped, so a flood cannot stop your existing records from
being refreshed.

Counts live in memory and reset on restart, so the cap limits the *rate* of
discovery under one parent, not the total.

### The defaults, on live data

All three filters are on out of the box. `ctmon` prints them at startup:

```console
INFO filters skip_suffixes=17 parent_cap=20 parent_window=10m0s max_depth=1
```

One minute of CT through a plain `ctmon run`:

```
certs=12024 names=23446 from_san=11188
too_deep=7835 blocked=3219 capped=102 dup=2417
new=9873
```

Of 23,446 names, depth dropped 33%, the blocklist 14%, and the cap 0.4%,
leaving 9,873 stored domains — 42% of what came in.

To see everything CT offers, turn the lot off:

```console
$ ctmon run --db ct.db --max-depth 0 --default-skip=false --parent-cap 0
```

Each record holds where the name came from, when it was first and last seen,
and the result of fetching `https://<host>/`:

```console
$ ctmon get --db ct.db example.com
{
  "host": "example.com",
  "cert_name": "*.example.com",
  "origin": "cn",
  "from_wildcard": true,
  "source": "https://ct.googleapis.com/logs/us1/argon2026h2/",
  "issuer": "WE1",
  "first_seen": "2026-08-21T20:49:54.235102251Z",
  "last_seen": "2026-08-21T20:49:54.235102251Z",
  "seen_count": 1,
  "probed": true,
  "probed_at": "2026-08-21T20:50:09.874355393Z",
  "http_status": 200,
  "final_url": "https://example.com/",
  "body_size": 1503,
  "body_hash": "bd9b4042f1bdcd9a99a5ea9bc85660dab95b11111e636daeb70a876056d5e52f",
  "probe_count": 1
}
```

The body hash makes the store useful beyond a name list: identical hashes
across hosts identify parked pages and shared boilerplate, and a hash that
changes between probes tells you the site changed. When a re-probe produces a
different hash, the old one moves to `prev_body_hash` and `changed_at` is set.

## Why not the `kv` project

The original plan was to persist into `~/projects/kv`. That store does not fit
this data, for two reasons:

- **Keys cap at 16 characters** (`kv/MANUAL.md` §2). Most hostnames are longer,
  and `kv import` skips over-long keys silently.
- **Values are not free-form.** A `kv` value is a `(algorithm, digest)` pair
  that must verify as `algo(key)`. There is no slot for an unrelated value such
  as the hash of a page body.

`ctmon` uses [bbolt](https://github.com/etcd-io/bbolt) instead: an embedded,
single-file, pure-Go key/value store with arbitrary keys and values. The store
is isolated behind `internal/store`, so swapping backends means implementing
that one interface. How records are laid out inside it is described in
[Storage](#storage).

## Install

```bash
go build -o ctmon ./cmd/ctmon
```

Go 1.24 or later. The database is a single file; point `--db` anywhere.

## Feeds

Two sources feed the same pipeline, and both run by default (`--source both`):

- **`certstream`** connects to an aggregated CT firehose over a websocket. It
  starts instantly and costs one connection, but it depends on a third party
  staying up and honest.
- **`ctlog`** polls CT logs directly over RFC 6962 (`get-sth`, `get-entries`).
  It depends on nobody but the logs, and it records how far it has read each
  log, so a restart resumes exactly where it stopped. Logs are discovered from
  Google's v3 log list, filtered to the ones usable and current; override with
  `--logs`.

Run just one with `--source certstream` or `--source ctlog`.

By default a newly seen log starts at its current tree head, so you get new
certificates rather than history. Pass `--from-start` to backfill a log from
index 0 — that is millions of entries per log, so use it deliberately.

### When a log goes bad

Logs degrade. One measured case: `ct2026-b.trustasia.com/log2026b` served 64
entries in 56.7 seconds at 2.8 KB/s while its own sibling `log2026a` served
the same 64 in 1.0 second, and Google's `xenon2026h2` in 0.08 seconds. A log
in that state cannot answer a 256-entry request inside the 60-second timeout,
and it gains entries faster than any client can read them. Three defences:

- **The batch size adapts per log.** `--batch` is a ceiling, not a promise. A
  failed `get-entries` halves it, down to a floor of 8; a good one raises it a
  step, back up to the ceiling. Asking a struggling log for the same 256
  entries over and over makes no progress at all, where 32 might.
- **The retry backoff resets after a healthy run.** The delay climbs 5s, 10s,
  20s … to a 10-minute cap, but a `follow` that lasted a minute before failing
  starts the next one at 5 seconds again. Otherwise a log that hiccups once an
  hour ends up waiting the maximum between every retry, forever.
- **`--max-lag` skips a hopeless backlog.** Set it and a log more than that
  many entries behind its tree head jumps to the tip, logging what it dropped.
  Off by default, because it is deliberate data loss — but a log five hours
  behind is serving history that reached the store through another log long
  ago, since certificates are logged to more than one.

```console
WARN ct log too far behind; skipped to tip log=https://ct2026-b.trustasia.com/log2026b skipped=16935
```

Set `--max-lag` well above what a log issues in one `--poll` interval, or it
skips every cycle and reads nothing: at 1,700 entries per second and a
30-second poll, anything under ~50,000 is too tight. Six figures is a
reasonable starting point. A log seen for the first time is never skipped, so
`--from-start` still means from the start.

## Commands

```console
ctmon run     [flags]    follow CT logs and record discovered domains
ctmon list    [flags]    list stored domains
ctmon get     <host>     show one record as JSON
ctmon stats              summarize the store
ctmon migrate [flags]    rewrite an old JSON database into the packed format
ctmon compact [flags]    repack the database into full pages
```

Useful `list` filters: `--with-hash`, `--wildcard`, `--changed`, `--since 1h`,
`--under example.com`, `--limit N`, `--json` for JSON lines.

```console
$ ctmon list --db ct.db --with-hash --limit 1
easyticket.de.mcas.ms	200	b3bb5c4b3924da3c9a3c6fad691b6e90d89b4bf6110526ffc795e6ff9c016a54	2026-08-21T20:49:45Z

$ ctmon list --db ct.db --under example.com     # the domain and everything under it
example.com	200	b3bb5c4b39...	2026-08-21T20:49:45Z
www.example.com	200	b3bb5c4b39...	2026-08-21T20:49:45Z

$ ctmon stats --db ct.db
domains:    21821
probed:     648
with hash:  334
wildcards:  2154
errors:     314
changed:    0

file size:  1.2 MiB
per record: 57 B
interned:   6 sources, 86 issuers, 29 error shapes
```

## How the pipeline handles load

CT issues certificates far faster than any polite crawler can fetch pages —
roughly 400 certificates per second against a default of 20 probes per second.
The pipeline splits accordingly:

1. **Recording is cheap and never dropped.** Store writers block rather than
   lose a discovery, so every hostname the feeds produce lands in the database.
2. **Probing is slow and sheds load.** A bounded worker pool fetches sites. If
   every worker is busy, the probe is skipped, not queued forever — the record
   simply stays `"probed": false`.
3. **The backfill sweep catches up.** Every `--backfill` interval (default one
   minute) `ctmon` walks the store for hosts still waiting on a probe and
   queues them at whatever pace the probers manage.

So `deferred` in the progress line is not data loss; it is work postponed. Set
`--reprobe 24h` to also re-fetch known hosts once a day, which is what turns
the store into a change monitor.

The feeds also repeat themselves — the same certificate arrives from certstream
and from the log it was written to, and packed certificates re-list the same
names — so a set of the last `--recent-hosts` hostnames (default 50,000)
squashes repeats before they cost a store read. This is why the two repetition
counters read the way they do: a name the set still remembers counts as `dup`
and stops there, and only a name it has forgotten reaches the store and counts
as `repeat`. On a short run the set swallows nearly everything, so `repeat`
sits at zero until the set has cycled — at live rates, a few minutes in. Lower
`--recent-hosts` to trade memory for store reads.

## Probing behavior

Probes fetch `https://<host>/` with a 10-second timeout, follow up to three
redirects, read at most 2 MiB, and hash exactly the bytes they read. TLS
verification is **off** by default: the point is to fingerprint whatever the
host serves, and hosts found through CT routinely serve mismatched, expired, or
not-yet-deployed certificates. Turn it on with `--verify-tls`.

Failed fetches are recorded, not discarded — `probe_error` says why, which
separates "does not resolve" from "resolves and refuses".

### Probes stay on the public internet

A hostname that resolves to a private address is not fetched:

```console
$ ctmon get --db ct.db intranet.example.com
  "probe_error": "Get \"https://intranet.example.com/\": dial tcp 10.0.0.7:443: refusing to probe a non-public address: 10.0.0.7"
```

Every name here comes out of a stranger's certificate, and a certificate for a
name pointing at `127.0.0.1` is trivial to obtain. Without the guard, anyone
who wants one can make your monitor fetch services on the machine it runs on
and read the status, size, and body hash back out of your store. `ctmon` blocks
loopback, RFC 1918, link-local — including the `169.254.169.254` cloud metadata
endpoint — carrier-grade NAT, multicast, and the unspecified and broadcast
addresses, in both IPv4 and IPv6.

The check runs on the resolved address just before the connection, not on the
name beforehand, so it also catches a redirect into your network and a name
that answers publicly once and privately the next time.

`--allow-private` turns it off, which is what you want when the point is
monitoring your own infrastructure and the store is not shared.

Tuning knobs: `--probe-rps`, `--workers`, `--probe-timeout`, `--dial-timeout`,
`--max-body`, `--user-agent`. Run with `--no-probe` to collect names only.
Every name filter runs before probing, so a filtered host is never fetched.

### What probing actually costs

Probes are bound by how long dead hosts hold a worker, not by `--probe-rps`.
Measured over 88,622 probes on a live store:

| outcome | share |
|---|---|
| answered | 64% |
| connect or handshake timeout | 19% |
| does not resolve | 12% |
| refused, reset, EOF, TLS error | 5% |

At 16 workers that came to 6.7 probes a second against a limit of 20, because
average latency was 2.4s and the 19% that never answer accounted for about
40% of all worker time. `--dial-timeout` is the knob for that: it bounds the
connect and the handshake, which is where those go, and `--probe-timeout` does
not — that one starts once a connection exists. Dropping it to `2s` reclaims
most of the 40%; the cost is losing hosts that are real but slow to answer.

Raising `--workers` is the other half. Goroutines waiting on a socket are
cheap, so the pool size is close to a free parameter: reaching the default
20/s limit takes about 48 of them at that latency.

### Fresh names come first

Two queues feed the probers. New discoveries go in one, the backfill sweep
fills the other, and most workers take a fresh name whenever one is waiting.

Without that split the sweep won: it queues thousands of hosts at a time and
takes minutes to drain them, so the single queue was always full and every new
discovery was shed. On a live store it showed up as hosts first seen in the
last hour being no likelier to have been probed (18%) than hosts from the day
before (22%), which is the wrong way round for a monitor that exists to notice
new things.

A quarter of the pool stays pinned to the backfill queue, so the backlog keeps
moving even while new names arrive faster than the probers can fetch them —
which, on live CT, is always.

Be deliberate about pointing this at the internet at scale. Every discovered
name gets one unsolicited HTTPS request from your address.

## Storage

Records are keyed by **reversed hostname** — `www.example.com` is stored as
`com.example.www` — and held in a packed binary form. Two consequences:

- Every name under one domain sorts into one contiguous run, so related
  records share pages and `--under example.com` is a range scan rather than a
  walk of the whole store.
- A record costs about **35 bytes**: 24 for the key, 11 for the value.

The value is small because almost nothing in a record is new information.
Measured over a real store, JSON spent 17.7% of its bytes on `source` (five
distinct values), 29.9% on timestamps written as RFC 3339 strings, 11.4% on
`cert_name` (derivable from the host in 100% of records), and 16.2% on three
booleans. So the packed format:

- **Interns** the log URI, the issuing CA, and the shape of a probe error into
  dictionaries. A probe error keeps its host substituted back in on read, so
  thousands of "no such host" failures share one entry.
- **Derives** `cert_name` from the host where it is the host, `*.host`, or the
  wildcard over the apex a `www` host sits under, and derives `final_url`
  where it is just `https://<host>/`.
- **Packs** the booleans and shapes into two flag bytes, stores timestamps as
  four-byte unix seconds with the later ones as varint deltas, and keeps
  digests as raw bytes rather than hex.

Body hashes stay full SHA-256. Timestamps lose sub-second precision, which is
the one thing the format gives up.

### Reading the store while it runs

A run holds bolt's exclusive lock on the database, so `stats`, `list`, and
`get` cannot open it — not even read-only, because the shared lock they would
take conflicts with the writer's:

```console
$ ctmon stats --db ct.db
error: open ct.db: timeout
```

Copying the file is not the answer either. `cp` reads it over several seconds
while it changes underneath, and the result mixes pages from two eras into a
tree whose cursor walks in circles. It looks like a working database until a
full scan repeats records forever.

Signal the run instead. `SIGUSR1` writes a consistent copy beside the live
file, from a read transaction inside the process that holds the lock, and the
run keeps collecting throughout:

```console
$ kill -USR1 $(pgrep -f "ctmon run")
$ ctmon stats --db ct.db.snap
domains:    1406056
probed:     80820
...
```

```
INFO snapshot written path=ct.db.snap size="96.3 MiB" took=1.2s
```

`--snapshot` puts it somewhere else. The copy lands via an atomic rename, so a
reader finds either the previous snapshot or the new one, never a half-written
file. Windows has no `SIGUSR1`, so there the run logs nothing about snapshots
and the database has to be stopped to read it.

### Migrating an existing database

`ctmon run` refuses a database in the old JSON format rather than misreading
it, and points at:

```console
$ ctmon migrate --db ct.db
migrated 21821 records and 9 log positions in 290ms
  in use:  10.5 MiB -> 1.2 MiB  (8.9x smaller)
  on disk: 16.0 MiB -> 2.0 MiB
  505 B/record -> 57 B/record
```

The original is only read; the result lands in `ct.db.packed` for you to move
into place.

### Compaction

Live writes arrive in random key order, so bolt splits leaf pages at half full
and the file drifts toward twice the size it needs. A store written by a live
run measured 69% full. `ctmon compact` replays it in key order into fresh
pages:

```console
$ ctmon compact --db ct.db
compacted in 21ms
  in use:  856.0 KiB -> 584.0 KiB  (1.5x smaller)
```

That took fill from 69% to 98%. Both commands read the source and write a new
file, so nothing is lost if they fail.

A long run does this for itself every `--compact-every` (default 24 hours):
`ctmon` rewrites the database beside the live one and swaps it in with an
atomic rename, so an interrupted compaction leaves either the old file or the
new one. Every store call pauses for the rewrite — 1.7 seconds for 141,818
records — and the feeds buffer meanwhile. Set `--compact-every 0` to turn it
off and run the command by hand instead.

```console
INFO compacted in_use="6.7 MiB" reclaimed="3.1 MiB" file="8.0 MiB" took=1.689s
```

Two sizes are worth separating. *In use* is pages holding data; on a real
141,818-record store compaction took it from 9.8 MiB to 6.7 MiB. *On disk* is
bolt's mmap high-water mark, which doubles as the store grows and never
shrinks — 16 MiB before, 8 MiB after. The file re-inflates as writes resume,
which is why this is a schedule rather than a one-time fix.

Raising bolt's `FillPercent` on the live path looks like the obvious way to
avoid the slack in the first place. It does the opposite. `FillPercent` sets
the point at which an over-full page splits, so a high value hands almost
everything to the first page and leaves the remainder a near-empty page that
soon splits again. Measured over 200,000 randomly ordered inserts:

| FillPercent | leaf pages full | pages allocated |
|---|---|---|
| 0.5 (bolt's default) | 70% | 14.96 MB |
| 0.75 | 57% | 18.15 MB |
| 0.9 | 35% | 30.03 MB |
| 1.0 | 16% | 66.27 MB |

Throughput moved by less than 6% across all four. Bulk paths are the exception
and do raise it: `migrate` writes pre-sorted keys, where filling a page to 95%
never leaves a remainder.

### Write throughput

bolt commits by waiting: a batch closes after 10 ms or 1,000 pending calls,
whichever comes first. With one writer that caps the store at roughly 100
records per second, and each additional writer adds about that much again.
`--writers` defaults to 4, which comfortably covers the default intake of ~165
records per second; raise it if you turn the filters off.

## Layout

```
cmd/ctmon            command line: run, list, get, stats
internal/source      certificate feeds (certstream, RFC 6962 log poller)
internal/domain      CN and SAN → hostname expansion, validation, depth
internal/probe       HTTPS fetch and body hashing
internal/store       packed records, dictionaries, migration, compaction
internal/pipeline    wiring: filters, record, probe, backfill
```

## Tests

```bash
go test -race ./...
```

The suite covers CN and SAN expansion, subdomain depth against the public
suffix list, the suffix blocklist and parent cap, record round-trips through
the packed codec, key reversal and range scans, migration from the old format,
compaction, probe hashing (including the body cap and redirects), certstream
message parsing, and the pipeline end to end against a local HTTPS server.
