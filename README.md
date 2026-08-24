# ctmon — a certificate transparency domain monitor

[![CI](https://github.com/0xMattijs/ctmon/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMattijs/ctmon/actions/workflows/ci.yml)

`ctmon` watches Certificate Transparency logs for newly issued certificates,
derives hostnames from each certificate's Common Name and subject alternative
names, and records every hostname together with a SHA-256 hash of the HTML it
serves over HTTPS.

```console
$ ctmon run --db ct.db
INFO discovered ct logs rfc6962=17 tiled=11 lookahead=4800h0m0s
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

Three sources feed the same pipeline. Two of them run by default
(`--source both`):

- **`certstream`** connects to an aggregated CT firehose over a websocket. It
  starts instantly and costs one connection, but it depends on a third party
  staying up and honest.
- **`ctlog`** polls CT logs directly over RFC 6962 (`get-sth`, `get-entries`).
  It depends on nobody but the logs, and it records how far it has read each
  log, so a restart resumes exactly where it stopped. Logs are discovered from
  Google's v3 log list; override with `--logs`.
- **`tiled`** reads Static CT API logs: a signed checkpoint saying how big the
  tree is, and the entries themselves downloaded as fixed-size tiles off static
  storage. Same discovery, same positions, same guarantees; override with
  `--tiled-logs`.

Run one with `--source certstream`, or several with a comma-separated list.
`--source all` is every one of them. `both` predates the tiled reader and still
means what it meant then — `certstream,ctlog` — because widening it would
double the request load of every existing run without anyone asking.

By default a newly seen log starts at its current tree head, so you get new
certificates rather than history. Pass `--from-start` to backfill a log from
index 0 — that is millions of entries per log, so use it deliberately.

### Two kinds of log

Google's v3 list carries two kinds of log per operator, and they are two
protocols rather than two spellings of one. An RFC 6962 log answers `get-sth`
and `get-entries`. A Static CT API log answers neither:

```console
$ curl -s https://luoshu2027.trustasia.com/luoshu2027/checkpoint | head -3
luoshu2027.trustasia.com/luoshu2027
77756735
rYbKBRn9UQA5cpgyjeBE4UtGU4VdBhxI9y2zQdrN7ds=
$ curl -so /dev/null -w '%{http_code}\n' https://luoshu2027.trustasia.com/luoshu2027/ct/v1/get-sth
404
```

So they get separate readers and separate flags. A monitoring prefix handed to
`--logs` would fail every poll and back off forever, which is a slow way to
learn the difference.

The reason to read both is the direction of travel. Static CT is where new
shards are being stood up, so the tiled half of the list grows on its own as
operators move shards across, and a run watching only the RFC 6962 half goes on
looking complete right up to the day there is nothing left on it. A run that is
not following them says how many it is leaving:

```console
$ ctmon run --source ctlog
INFO discovered ct logs rfc6962=17 tiled=11 lookahead=4800h0m0s
WARN static ct logs on the list are not being followed count=11 follow_them_with="--source ...,tiled"
```

That number is not the same as certificates missed. Chrome's policy has every
certificate logged to more than one log, so most of what lands in a tiled log
is also in an RFC 6962 log this already reads. It is coverage, not volume: the
question it answers is what happens the day that stops being true.

### Reading a tiled log

Entries come in tiles of 256, and a tile is either full or partial — different
resources with different names, and the partial one stops existing the moment
the tree grows past it. Positions are still leaf indexes, so a restart resumes
inside a tile: the tile holding the position is fetched whole and read from the
middle.

Three answers from a tiled log are not failures, and are not treated as any:

- **A tile the checkpoint promised and the storage has not got yet.** A log
  counts an entry in its tree before every edge serving its tiles has the tile
  holding it. Measured against `luoshu2027` the gap closed in under two
  minutes. The reader waits it out rather than tearing down the follower, and
  says so if it lasts.
- **A partial tile that has just been replaced.** Same handling, and it is the
  common case on a busy log: the tree grows between reading the checkpoint and
  fetching the tile it described.
- **`429 Too Many Requests`.** Tiles come off ordinary object storage and
  several operators rate-limit it. Geomys answers with a `Retry-After` naming
  the instant the bucket refills; the reader waits exactly that long, capped at
  ten minutes, and keeps the follower alive. Backing the follower off instead
  would wait without knowing what for, and double past it.

Anything else — a broken tile, a tile that reframes entries already read, an
unreadable checkpoint — fails the follower and earns the ordinary backoff.

Nothing here verifies the checkpoint signature. That would mean carrying each
log's public key from the list and implementing the RFC 6962 note signature
scheme, and it would put this feed ahead of the RFC 6962 one, which asks for an
STH without a public key and so does not verify either. Both trust HTTPS to the
log's own name, for the same reason: this is looking for hostnames, and a log
that lied about its tree could only make it look at more of them.

### The log list moves

Logs are sharded by time, and most operators roll over every half year. A run
that discovered its logs at startup and never looked again outlives them: at a
boundary the whole set stops accepting certificates at once, and the monitor
keeps politely polling shards nobody writes to while missing the ones that
replaced them. With `--source both` the firehose covers for it, so the only
sign is the `ctlog` share of the counters going quiet.

So the list is re-read every `--log-refresh` (24h by default, `0` disables) and
the followers are brought in line with it: a log the list has added gets one, a
log it has dropped loses its. Both sides are logged. Both readers work this
way, and share the code that does it — the protocols differ, the bookkeeping
around them does not. A refresh that fails, or
that comes back empty, changes nothing — a list that would not load is no
reason to stop following logs that are working.

The stored position of a log that left is kept, and logged on the way out.
Shards come back, and resuming one at its tip would lose everything logged
while it was away. A log that was behind when it left — a degraded one, or one
`--max-lag` has been letting slip — leaves entries after that position that
nothing reads unless the list brings it back.

`--logs` and `--tiled-logs` name a set explicitly and are never second-guessed:
no discovery at startup, and no refresh after it. One pass over the list serves
both readers, so a run following both kinds fetches it once to start.

### Shards run ahead of the clock

A shard's temporal interval bounds the certificate's `NotAfter`, not when it
was submitted. A certificate is logged to the shard covering its expiry, so the
shard new certificates land in runs ahead of the calendar by up to the maximum
validity period — 200 days from March 2026, 100 from March 2027.

Filtering the list to shards whose interval contains *now* therefore misses the
one being written to. A certificate issued today with 200 days to run has a
`NotAfter` in March 2027 and goes to `argon2027h1`: usable, listed, and, under
that rule, not followed. It is wrong for most of each shard's life rather than
just at the boundary, and worst in the months before a rollover.

So the window is a lookahead, not a point. A shard is followed when it has not
ended *and* it opens within `--log-lookahead` (200 days by default) of now.
Against today's list that is 17 RFC 6962 logs where the point rule gives 9, and
each of the extra 8 is one certificates are genuinely being written to.
Dropping the bound entirely would give 21, including shards that do not open
until late 2027 and answer every poll with nothing. The same window judges
tiled shards, which are sharded by the same calendar for the same reason.

The default is deliberately the older, longer validity limit. Being late to
shrink it costs a `get-sth` per poll against a few empty shards; being early to
shrink it loses certificates.

The real cost is that it roughly doubles the request load of `--source ctlog`,
which is what the flag is there for. `--log-lookahead 0` asks for no lookahead
and follows only the shards open now — the old behaviour, at half the requests.
That is a reasonable trade on `--source both`, where the firehose still carries
what the successor shard is being sent, and a bad one on `--source ctlog`
alone, where nothing else is watching it.

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
ctmon prune   [flags]    delete records a retention rule has aged out
ctmon migrate [flags]    rewrite an old JSON database into the packed format
ctmon compact [flags]    repack the database into full pages
```

`list`, `get`, and `stats` only read. They open the database read-only and
refuse a path that does not already name one, rather than creating an empty
store and reporting zeros about it:

```console
$ ctmon stats --db ct.dbb
error: ct.dbb: no such database
```

`run` and `prune` are the two commands that write to `--db`; `run` also
creates the database on first use. `migrate` and `compact` read `--db` and
write to `--out`, leaving the original untouched.

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

file size:  2.0 MiB
in use:     1.2 MiB
per record: 57 B
interned:   6 sources, 86 issuers, 29 error shapes
```

The two sizes answer different questions. *File size* is what the file
occupies, which is what a disk quota cares about. *In use* is what its pages
hold: bolt grows the file in mmap-sized steps and keeps freed pages on a
freelist for reuse, and neither counts toward this number. The gap between the
two is room the store can fill without growing.

## How the pipeline handles load

CT issues certificates far faster than any crawler can fetch pages — roughly
400 certificates per second, which after filtering is still around 100 new
hostnames a second. The pipeline splits accordingly:

1. **Recording is cheap and never dropped.** Store writers block rather than
   lose a discovery, so every hostname the feeds produce lands in the database.
2. **Probing is slow and sheds load.** A bounded worker pool of `--workers`
   (default 256) fetches sites. If every worker is busy, the probe is skipped
   rather than queued in memory forever — the record stays `"probed": false`
   and its place in the pending queue is what remembers it.
3. **The backfill sweep catches up.** Every `--backfill` interval (default ten
   seconds) `ctmon` takes the hosts that have waited longest off the pending
   queue and hands them to the probers at whatever pace they manage.

So `deferred` in the progress line is not data loss; it is work postponed, and
the postponement is written down: every host that wants a probe goes on the
pending queue in the same transaction as its record, so a host cannot end up
wanted-but-forgotten however the run ends. `throttled` is the other
postponement — a probe held back because its destination address had already
had its share this second. Set `--reprobe 24h` to also re-fetch known hosts
once a day, which is what turns the store into a change monitor.

One counter is not about certificates at all. `store_errors` counts reads and
writes the database refused. Everything in the pipeline logs a failure and
carries on, which is right for one bad host and wrong as the only trace of a
full disk: a run that has stopped being able to write looks exactly like a
quiet hour otherwise. Anything but zero there means discoveries are being
dropped.

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

Probes resolve the name, fetch `https://<host>/` with a 6-second budget end to
end, follow up to three redirects, read at most 2 MiB, and hash exactly the
bytes they read. TLS verification is **off** by default: the point is to fingerprint whatever the
host serves, and hosts found through CT routinely serve mismatched, expired, or
not-yet-deployed certificates. Turn it on with `--verify-tls`.

Failed fetches are recorded, not discarded — `probe_error` says why, which
separates "does not resolve" from "resolves and refuses".

A failure that says nothing about the host is not recorded at all. A resolver
that times out or returns SERVFAIL has not answered the question, so the probe
is put off and tried again rather than written down; only `no such host` is
treated as an answer. Without that distinction a busy resolver writes its own
bad afternoon into thousands of records as if it were a fact about the hosts.

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

Tuning knobs: `--workers`, `--probe-rps-per-ip`, `--probe-timeout`,
`--dial-timeout`, `--tls-timeout`, `--resolvers`, `--resolve-concurrency`,
`--max-body`, `--user-agent`. Run with `--no-probe` to collect names only.
Every name filter runs before probing, so a filtered host is never fetched.

### What probing actually costs

Probing is bound by DNS, then by dead hosts, and hardly at all by the thing
that used to limit it. The old defaults — 16 workers under a shared 20
requests-per-second limit — managed **17.7 probes a second, 74% of them
failing**, against an intake of about 108 new hostnames a second.

Three things were in the way, and only the first was obvious:

1. **One rate limit doing two jobs badly.** A limit shared across all hosts is
   not politeness — every probe is a different site getting a single request,
   so the sites cannot tell. `--probe-rps-per-ip` rations by destination
   address instead, which is the unit a site can object to.

   But the shared limit was doing a second job worth keeping, and it is not
   about the sites at all. See [What this does to your
   network](#what-this-does-to-your-network).
2. **Names resolved by the HTTP client.** A name that does not exist cost a
   worker the whole dial timeout. Resolving first makes it cost a DNS answer.
3. **The resolver itself.** This is the one that matters, and it does not
   appear in any of `ctmon`'s own knobs.

#### The resolver is the ceiling

Measured against the same 1,000 hostnames drawn from a live store, 8-second
timeout:

| resolver | lookups/s | no answer |
|---|---|---|
| `systemd-resolved` forwarding, concurrency 64 | 46 | 11.5% |
| `unbound` recursing from the root, concurrency 64 | 49 | 41.4% |
| `unbound` forwarding to six upstreams, concurrency 64 | 84 | **2.2%** |
| `unbound` forwarding to six upstreams, concurrency 256 | 90 | **1.7%** |

Two results worth keeping. A local forwarder saturates early: `systemd-resolved`
tops out near 126 lookups a second and drops 12% of them even at concurrency
8, so several hundred workers all asking at once turn into recorded failures
rather than answers. And **recursing from the root is worse than forwarding**
for this workload — the slow, flaky part is the authoritative servers of the
junk domains certificate transparency is full of, not the resolver, and a
forwarder gets those from a cache that is already warm.

So point `--resolvers` at something that can take the load:

```console
$ ctmon run --db ct.db --resolvers 127.0.0.1:53 --resolve-concurrency 256
```

`--resolve-concurrency` (default 64) bounds lookups separately from
`--workers`, because the two are different numbers: workers wait on sockets and
cost almost nothing, while their lookups land on one process that starts
failing rather than queueing when too many arrive at once. Leave it near the
default when using the system resolver; raise it when you have given `ctmon` a
resolver that can keep up.

The feed uses the same resolver as the probes. It has to: a run probing hard
enough to saturate DNS otherwise starves its own source of certificates, which
shows up as every log failing `get-sth: ... server misbehaving` and the feed
stopping altogether while the probers carry on. That shared resolver is
`internal/resolve`, built once at startup and handed to both, so neither owns
the thing they depend on equally.

Both feeds go through it — the log poller and the certstream websocket, which
re-resolves the firehose on every reconnect and is therefore exactly the wrong
thing to leave on a starved resolver.

The feeds and the probes dial it differently. A probe may only reach a public
address, because anyone can have a certificate issued for a name pointing at
`127.0.0.1`. A CT log came from `--logs` or from the log list, and the firehose
from `--certstream-url`, which is your own configuration, so the feeds dial
whatever the name resolves to.

#### When the resolver gives up

Two counters say a probe did not happen. `throttled` is the monitor pacing
itself — a destination address had already had its share this second.
`unresolved` is the resolver not answering, and it is the one to watch: it
means probes are being attempted faster than DNS can serve them.

A lookup that fails is only put off while the resolver is failing *generally*,
judged over the last thousand or so lookups. Once it is answering again, a name
that still will not resolve is a fact about that name and gets recorded.
Without that distinction a domain whose nameservers are permanently dead never
gets marked probed, so it comes back on every sweep for as long as the database
exists — measured at 156,130 deferrals against 9,981 real probes before the
rule was added, and 4,718 after.

For the same reason the backfill sweep stops while the resolver is down:

```console
WARN backfill paused: the resolver is not answering
INFO backfill resumed: the resolver is answering again
```

Feeding the backlog through a resolver that cannot answer is worse than doing
nothing. Every host leased comes straight back undone, so the sweep spins
through the queue rewriting entries and the resolver never gets the quiet it
needs to recover.

An `unbound` configured as a caching forwarder is a good answer. The settings
that mattered were plenty of outgoing ports, a large message cache, no DNSSEC
validation — a validating resolver answers SERVFAIL for the many CT names whose
owners have broken their own — and `forward-addr` lines for several upstreams
so that no single provider rate-limits the monitor.

#### Timeouts

`--dial-timeout` (2s) bounds the TCP connect, `--tls-timeout` (3s) the TLS
handshake, and `--probe-timeout` (6s) the whole probe. The handshake gets its
own, larger budget on purpose: a connect either lands quickly or not at all,
but a handshake is several round trips to a server that has already answered,
and a budget tight enough for the connect turns slow-but-real sites into
failures.

These bound probes only. The feeds have their own, `--feed-dial-timeout`
(10s), because two seconds is right for shedding a host out of CT that will
never answer and wrong for a CT log on the other side of the world having a
slow moment — there it costs a reconnect and a backoff.

Raising `--workers` is close to free — goroutines waiting on a socket cost
almost nothing — which is why the default is 256. It is also not the knob that
will help you once DNS is where the time goes.

### What this does to your network

Probing is thousands of short-lived connections to thousands of strangers,
which is a traffic shape most home and office networks never see. Two things
about the way `ctmon` probes make it harder on the network than the byte count
suggests:

- **Every probe is a new connection.** Keepalives are off, because a host is
  fetched once and almost never again, so a pool would only hold idle sockets
  open to sites the monitor has finished with.
- **A closed connection is not a freed one.** Whatever does NAT between this
  machine and the internet keeps a translation entry for a while after the
  connection ends — typically a minute or two.

Steady-state entries are roughly the probe rate times that timeout. At the
default `--probe-rps 100` and a two-minute timeout, that is around 12,000
entries held at once. Consumer routers run out well below that, and when the
table fills it is not the monitor that suffers, it is everything else sharing
the connection.

So `--probe-rps` is a ceiling on the monitor as a whole, and the number to turn
down first if probing is making the network unhappy. `--probe-rps 0` removes it
for the case where the path out is yours to saturate.

DNS deserves the same thought. Hundreds of lookups a second is its own kind of
load, and if the machine resolves through the router — which is the default on
most networks — that lands on the same box. Pointing `--resolvers` at a local
`unbound` forwarding to upstreams on the internet takes that traffic off the
router entirely, which is worth doing for the router's sake even where DNS
throughput is not the problem.

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

### The backlog is a queue, not a scan

The backfill sweep used to walk the domain bucket from the top and take the
first few thousand hosts that still wanted a probe. Records are keyed by
reversed hostname, so that walk went in TLD-alphabetical order — and because
new discoveries kept landing in the part of the keyspace it had already passed,
the walk never got far. Measured on a live store of 2.1M names:

| TLD | share probed |
|---|---|
| `.ai`, `.app`, `.at`, `.au`, `.be`, `.biz` | 82-97% |
| `.br` | 28% |
| `.com`, `.de`, `.net`, `.org`, `.uk`, `.xyz` | ~3% |

Roughly 110,000 records sat in front of that frontier and 1,950,000 behind it.
`.com` is 42% of the store, and the 3% it had were the ones the fresh queue
caught on the way past — the sweep had never reached them and, at the rate new
`.b`-and-earlier names arrived, never would have. Coverage was not a sample of
the store. It was an alphabetical prefix of it.

So the store now keeps the backlog explicitly, in a `pending` bucket keyed by
when each host's probe is due. The sweep takes the hosts that have waited
longest, whatever they are called. Two things follow from making it a real
queue:

- **A probe that is put off has a time attached.** A host turned away by its
  address's budget comes back in `30s`; a re-probe comes back after
  `--reprobe`. Both are the same mechanism as a first probe, just later.
- **Nothing is dropped by dying.** Hosts handed to a prober are *leased* rather
  than deleted: the entry stays, hidden, until `--backfill-lease` (default 30
  minutes) runs out. Finish the probe and it goes; kill the process mid-probe
  and the host comes back on its own.

`--backfill 0` turns the sweep off, and with it the queue: nothing would ever
take entries out, so nothing puts them in. Probing still happens, on names as
they arrive:

- A discovery is recorded and handed straight to a prober.
- A probe its address turns away is dropped rather than queued. The `throttled`
  and `unresolved` counters are the only trace.
- A re-probe is never scheduled, so `--reprobe` only reaches hosts a later
  certificate names again.
- Startup skips filling the queue from existing records, which is otherwise a
  walk of the whole store.

What that costs is every probe that could not happen the moment the name
arrived. A host shed because all the workers were busy, or turned away by its
address's budget, is recorded unprobed and nothing schedules it.

Those hosts are not lost. A run with the sweep off marks the database as
holding records the queue was never told about, and the next run that does
sweep fills the queue from the records again — the walk below — so they join
the backlog then:

```console
INFO a previous run recorded hosts without queuing them: filling the queue again
```

What the mode costs is the wait until such a run happens, and one full walk of
the store when it does.

`--backfill 0` is for a run you want to leave no backlog behind. It is not a
way to probe less.

Re-probing rides on the same queue. A finished probe schedules the next one,
and because that leaves every host probed before `--reprobe` was set out of the
queue entirely, changing the setting seeds the store again for the new policy.

The queue is filled from the records at startup whenever it may be missing
some: on a database written before the queue existed, after `--reprobe`
changes, and after a run with the sweep off:

```console
INFO filling the probe queue scanned=1640000 queued=1479642
INFO probe queue filled from existing records queued=1952082 took=37s
```

It resumes. The cursor is committed with each chunk, so a run interrupted part
way through a two-million-record store picks up where it stopped rather than
queueing everything twice.

`ctmon stats` reports the depth, and how long the host at the head of the queue
has been waiting — which is the number that says whether probing is keeping up:

```
queued:     1952082
waiting:    3h14m22s (oldest queued probe)
```

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
  dictionaries. A probe error is stored as its shape, with the hostname and any
  addresses lifted out and put back on read, so thousands of failures that
  differ only in where they were aimed share one entry.
- **Derives** `cert_name` from the host where it is the host, `*.host`, or the
  wildcard over the apex a `www` host sits under, and derives `final_url`
  where it is just `https://<host>/`.
- **Packs** the booleans and shapes into two flag bytes, stores timestamps as
  four-byte unix seconds with the later ones as varint deltas, and keeps
  digests as raw bytes rather than hex.

Body hashes stay full SHA-256. Timestamps lose sub-second precision, which is
the one thing the format gives up.

#### The shape of an error

Masking the hostname alone was not enough. The thing errors carry most is the
address, and it varies far more than the hostname does:

```
Get "https://<host>/": dial tcp 178.142.12.95:443: connect: connection refused
Get "https://<host>/": dial tcp 46.29.238.201:443: connect: connection refused
```

Interned whole, those are two entries, and the dictionary grew with the number
of addresses the prober had failed against rather than with the number of
things that can go wrong. On a live store that had reached 7,239 shapes in a
few days, of which 5,873 were used by exactly one record.

So an address is lifted out of the template and stored on the record, packed —
four bytes for IPv4, sixteen for IPv6 — and put back on read. Nothing is lost:
`ctmon get` still tells you which address a probe failed against. Measured over
all 170,410 error records on that store:

| | shapes | bytes |
|---|---|---|
| dictionary before | 7,239 | 621 KB |
| dictionary after | 2,391 | 228 KiB |
| addresses moved onto records | — | +680 KiB |
| **net** | | **+302 KiB** |

Space was never the point — that is 0.09% of a 313 MiB store either way. The
point is that the dictionary no longer grows with every address seen. What
remains is the smaller tail: an error naming some *other* host, like a redirect
target that failed to resolve, still interns that name. That is 2,391 shapes
rather than the 622 a full masking would give.

This is record format 3. Version 2 records are read exactly as they stand —
every record carries its own version byte, so the two layouts coexist in one
file and nothing has to be migrated. The stamp in the meta bucket is left
alone, so an older build still opens the database; it will refuse the records
it does not understand, loudly and one at a time, rather than misreading them.

### Reading the store while it runs

A run holds bolt's exclusive lock on the database, so `stats`, `list`, and
`get` cannot open it — not even read-only, because the shared lock they would
take conflicts with the writer's:

```console
$ ctmon stats --db ct.db
error: ct.db: database is held by another process; send it SIGUSR1 and read the snapshot instead
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

### Forgetting

The store otherwise only grows. Records are written and updated, never
removed, and compaction returns the slack between them without dropping any.
That is the right default for a discovery tool — a hostname seen once is
evidence, and evidence you threw away is not evidence you can go back to — but
it leaves no answer to the questions an operator eventually has.

`ctmon prune` is that answer, and it is the only command that deletes
anything:

```console
$ ctmon prune --db ct.db --unseen-for 90d       # no certificate has named it in this long
$ ctmon prune --db ct.db --failed-since 30d     # probed, never answered, discovered a while ago
$ ctmon prune --db ct.db --under workers.dev    # a platform and every tenant under it
```

The last one is the case with no other workaround. `--skip-suffix` mutes a
hosting platform going forward and leaves however many thousand of its tenants
already recorded; this is how you clear them out afterwards.

`--failed-since` means "has been failing this long", and asks two things of a
record: that it was discovered before the cutoff, and that its last probe was
too. A record does not store when it *started* failing, so the rule
approximates it from both ends. On FirstSeen alone, a host discovered months
ago that only now reaches the front of a deep queue would be deleted an hour
after its first probe returned a transient failure — the backlog delay, not
the host, being what aged it past the cutoff. Under `--reprobe` the rule
narrows instead, since a host tried this morning stops matching; that is the
safe direction for a rule that deletes.

**Nothing is deleted without `--apply`.** Without it prune runs the same walk
and reports what matched, so what it prints is what `--apply` would remove and
not an estimate of it:

```console
$ ctmon prune --db ct.db --failed-since 1d
170355 of 3131473 records match, and their queue entries with them (1.5s)

Nothing was deleted. Add --apply to remove them.
```

Durations here take days as well as the usual units, because retention is
something people count in days: `90d`, `1d12h`, and `36h` all work.

Rules combine with **and**, not or. `--under workers.dev --failed-since 30d`
deletes tenants of that platform that have never answered, and leaves the ones
that have. At least one rule is required — `ctmon prune --apply` with no rule
would empty the store, and there is no way to type that on purpose.

`--under` is a range scan, which is what reversed keys buy. On a 3.1M-record
store, scoping to one parent found its 9,892 records in **10 ms**; the same
question asked of the whole store takes 1.5 seconds.

Queue entries go with the records. A pruned host leaves entries in the pending
queue pointing at nothing, which the sweep already drops on sight — but only
one lease at a time, so a large prune would leave the queue dragging behind
the store for days. Prune reconciles the two itself, in one pass over the
queue after the records have gone.

That pass runs on every `--apply`, including one that matched no records, and
it is what dominates a small prune: deleting 9,892 records took 10 ms, and
walking the 3.9M-entry queue behind it took seven seconds. Running it
unconditionally is what makes an interrupted prune safe to repeat. The gap
between the two halves is the wide one, so that is where an interruption
lands; a second run that stopped on finding no records left to delete would
never reach the entries the first one orphaned.

Interned values go too. A dictionary entry is written the first time a record
needs it and was never removed, which was invisible while the store only grew:
delete the last record using a vocabulary and the entry stayed, with `stats`
counting it forever. `--failed-since` shows it worst, since it deletes exactly
the records carrying a probe error:

```console
$ ctmon prune --db ct.db --failed-since 1d --apply
deleted 170355 of 3131473 records and 65982 queue entries in 8.6s
forgot 7244 interned values no record still uses (607.3 KiB): 0 sources, 4 issuers, 7240 error shapes
```

That takes the `stats` line from `7250 error shapes` against 170,410 failing
records to `10` against 55 — a number that means something again. Ids are not
renumbered, which is what makes the sweep cheap: nothing indexes them densely,
so an unreferenced entry simply goes and no record is re-encoded. It costs one
extra walk of the records, and only runs when records were deleted.

Deleting frees pages without shrinking the file, so `--compact` repacks in
place afterwards:

```console
$ ctmon prune --db ct.db --failed-since 1d --apply --compact
deleted 165840 of 3121581 records and 65829 queue entries in 10.8s
compacted:
  in use:  500.4 MiB -> 307.8 MiB  (1.6x smaller)
  on disk: 521.1 MiB -> 313.7 MiB
```

Two things prune refuses. A database a run is holding, because prune writes
and bolt gives the writer an exclusive lock — the snapshot route the reading
commands suggest is no help here, since deleting from a copy leaves the
original as it was:

```console
$ ctmon prune --db ct.db --unseen-for 90d --apply
error: ct.db: database is held by another process; prune writes to the database, so stop the run first
```

And a snapshot itself, when asked to delete from it. Pruning a snapshot would
appear to work and change nothing, since the next `SIGUSR1` overwrites it from
the live database:

```console
$ ctmon prune --db ct.db.snap --unseen-for 90d --apply
error: ct.db.snap is a snapshot, and pruning it would change nothing: the next
snapshot overwrites it from the live database. Stop the run and prune ct.db instead
```

Counting against a snapshot is allowed, and is the useful thing to do with
one: while a run holds the live database the snapshot is the only readable
copy, and "how many records would this rule remove?" is exactly the question
worth asking of it. A counting run takes a read-only handle, so it cannot
write to the copy even by accident.

That guard recognizes a snapshot by its `.snap` name, which is all it has to go
on — prune cannot see the flags the run was started with. A run using
`--snapshot /var/backup/ct.copy` produces a snapshot prune will delete from
quite happily, so keep the default suffix if you want the guard.

A prune that is interrupted leaves the store consistent — it has simply
deleted fewer records than it was asked to, because the walk commits in chunks
rather than holding millions of deletions in one transaction. Running it again
finishes the job, records and queue both.

Two rules prune will not take. A retention window of zero or less, which names
a policy nobody can mean and which the layer above would read as no rule at
all. And `--under .`, or anything else that trims down to nothing: it names no
domain, and the scope it would collapse to is the whole store, so the flag
typed to make a prune narrow would be the one that emptied it.

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

Two sizes are worth separating. *In use* is pages holding data, with the
freelist left out; on a real 141,818-record store compaction took it from
9.8 MiB to 6.7 MiB. *On disk* is the file, which bolt grows in mmap-sized
steps and never shrinks — 16 MiB before, 8 MiB after. The file re-inflates as
writes resume, which is why this is a schedule rather than a one-time fix.

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
cmd/ctmon            command line: run, list, get, stats, prune
internal/source      certificate feeds (certstream, RFC 6962 poller, Static CT reader)
internal/domain      CN and SAN → hostname expansion, validation, depth
internal/resolve     caching DNS front end, shared by the probes and the feed
internal/probe       HTTPS fetch and body hashing
internal/store       packed records, dictionaries, migration, compaction, pruning
internal/pipeline    wiring: filters, record, probe, backfill
```

## Tests

```bash
go test -race ./...
```

GitHub Actions runs the same suite, plus `go build`, `go vet`, and a `gofmt`
check, on every push to `main` and on every pull request. The workflow reads
its Go version from `go.mod`, so the two cannot drift.

The suite covers CN and SAN expansion, subdomain depth against the public
suffix list, the suffix blocklist and parent cap, record round-trips through
the packed codec, key reversal and range scans, migration from the old format,
compaction, probe hashing (including the body cap and redirects), DNS caching
and the resolver-health judgement, certstream message parsing, the Static CT
wire format against two entries captured byte for byte off a real log, what a
tiled reader does with a tile that is missing or a log that refuses to be read
this fast, what the pipeline does when the store refuses a write, and the
pipeline end to end against a local HTTPS server.
