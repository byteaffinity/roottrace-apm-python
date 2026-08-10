# Changelog

## 0.4.5 - 2026-08-09

- **Metadata only: the repository moved to the `byteaffinity` organization.**
  Every project URL on PyPI still pointed at the previous owner. A published
  version's metadata cannot be edited, so correcting a link costs a release.
  No behaviour changed; 0.4.5 is 0.4.4 with the URLs corrected.

## 0.4.4 - 2026-08-05

- **Fixed: the wrapper reported itself as 0.4.2 for the whole of 0.4.3.** The
  0.4.3 release bumped the packaging metadata and left the `VERSION` constant
  behind, so every 0.4.3 install sent `wrapper_version: "0.4.2"` on each ingest
  payload and a `roottrace_apm-python/0.4.2` User-Agent. Only the reported
  version was wrong; nothing else behaved differently.
- **0.4.3 is gone from PyPI and is not coming back.** On 2026-08-05 every
  roottrace-apm file disappeared from the index. Why it happened has not been
  established. PyPI never allows a deleted filename to be uploaded again, so
  0.4.3 cannot be restored and this release replaces it. There are no other
  changes: 0.4.4 is 0.4.3 plus the version fix above.

## 0.4.3 - 2026-07-31

- **Security sinks.** The wrapper now reports when instrumented code reaches a
  call site an attacker needs (spawning a process, or `pickle.loads`) to
  `POST /apm/security-events`. Because it fires inside a transaction the report
  carries the request that caused it: trace id, endpoint, and method, with the
  client address resolved server-side from the connection rather than trusted
  from the reporting process.
  - **The fact, never the payload.** The executable is recorded; argv is not,
    because an attacker's arguments *are* the exfiltration.
  - **Deliberately narrow.** `eval`/`exec` and `open()` would catch more, and
    catching them means patching builtins across every library in the process.
    For a wrapper whose first promise is that it cannot break the application,
    that trade is not worth making. `subprocess` and `pickle` are attributes on
    their own modules, so wrapping them touches nothing else.
  - Buffer capped at 100 events between flushes and dropped rather than
    retried: a process being driven by an attacker outruns any flush interval,
    and an unbounded queue inside the victim is its own denial of service.
  - Off with `security_sinks=False` on `init()`.

## 0.4.2 - 2026-07-30

- **Fixed: `upload_interval_seconds` did nothing.** The server sends it, the
  RootTrace UI offers it as a control between 15 and 900 seconds, and this SDK
  clamped it on arrival and then never read it: profiles were drained on the
  metric flush cadence instead. That is 30 seconds by default and can be set to
  5 via `ROOTTRACE_APM_INTERVAL_SECONDS`, so a service could upload twelve
  slivers where the configured window asked for one profile. The Go and Java
  SDKs already gated on this; Python and Node did not. Uploads now happen once
  per configured interval, timed from when the profiler started so the first
  one covers a whole window. Flamegraphs were never wrong, the server merges
  everything into five-minute buckets regardless, but the setting was a lie
  and the upload count was several times what was asked for.

## 0.4.1 - 2026-07-30

- **Fixed: profiling did not start for the first minute of a host's uptime.**
  The "has the poll interval elapsed" guard compared `time.monotonic()` against
  an initial `0.0`, but `time.monotonic()` is uptime on Linux, so a process
  starting in a freshly booted container read a clock still in single digits
  and skipped its first config fetch until the *host* passed 60 seconds.
  Long-lived hosts were unaffected, which is exactly why it survived local
  testing and only surfaced on CI runners. The initial value is now `-inf`, so
  "never fetched" always counts as due.
- Lint: the ruff rule set is now selected explicitly in `pyproject.toml` and
  the version is pinned in CI. Ruff's defaults are not a stable contract,
  0.16 widened them, which failed the build on 41 findings in code nobody had
  touched.

## 0.4.0 - 2026-07-30

- **Continuous profiling**, off until enabled from the RootTrace UI. The SDK
  polls `GET /api/apm/config` on the flush loop and starts nothing on its own,
  so the switch is reachable during the incident it is causing rather than
  needing a redeploy.
  - **Wall-clock, across every thread, and labelled as such.** A daemon thread
    reads `sys._current_frames()` at the configured rate. True CPU sampling in
    CPython means `setitimer(ITIMER_PROF)`, whose signal only ever reaches the
    main thread (useless in a threaded web server), so the honest measurement
    is the one taken. Nothing calls it CPU.
  - **Fails closed.** If the config cannot be fetched, profiling does not
    start; a running profiler keeps its current settings rather than being
    torn down for a transient blip.
  - **Bounds enforced here as well as on the server** (10–200Hz among others),
    so a compromised or spoofed control plane cannot spin a sampling loop
    inside the process.
  - **Samples are weighted by the period actually achieved**, not the one
    requested. Under the GIL a sampler competing with a hot loop is scheduled
    late; at the nominal period every duration would be understated by exactly
    the fraction of ticks that were missed.
  - Overhead is measured and reported on each upload, including the sampling
    itself. Profiles are dropped rather than retried on upload failure: they
    are large and statistical, and a retry queue inside a customer process is
    the worse outcome.
  - Frames are `module.function`, deliberately without line numbers, so a
    function that got slower reads as the same function across a deploy
    instead of one frame vanishing and another appearing.
- Stdlib only, as before. No native dependencies.

## 0.3.2 - 2026-07-22

- Flush-failure warnings now name the endpoint they were sending to
  (`flush of N metric entries to <url> failed: ...`), so a DNS or
  connectivity failure points at the host that needs fixing instead of
  leaving the target implicit.

## 0.3.1 - 2026-07-21

- `RootTraceLogHandler` now includes the formatted traceback in the shipped
  message when a record carries `exc_info`, so `logging.exception(...)`
  ships what it prints, inside the same 8KB message cap. Previously the
  traceback was silently dropped and an error log arrived as its first line
  only.

## 0.3.0 - 2026-07-15

- Latency histograms: every timer metric and transaction group now carries
  an optional `buckets` object, a log2 histogram (4 buckets per octave,
  index `min(127, max(0, floor(log2(max(d, 0.001)) * 4) + 40))`, so 1ms is
  bucket 40 and 1000ms is bucket 79) of the durations since the last flush,
  so the dashboard can compute real percentiles instead of inferring them
  from an average. Buckets merge back with everything else on a failed
  flush. The field is additive and optional: servers that ignore it read
  the payload exactly as before.
- `AsgiMiddleware`: ASGI 3 middleware for FastAPI/Starlette with the same
  metrics, transactions, `traceparent` adoption, request context, and error
  capture as the WSGI middleware. Transactions are named from the resolved
  route template (`GET /orders/{order_id}`) when the framework publishes
  one, falling back to the raw path. Lifespan and websocket scopes pass
  through untouched.
- `python.eventloop.lag_ms` gauge: mean asyncio scheduling drift since the
  last flush, sampled by a 500ms monitor coroutine. Started automatically
  by `AsgiMiddleware`, or manually with `apm.watch_event_loop()`.
- `process.gil.lag_ms` gauge: mean oversleep of a 100ms daemon sampler
  thread. This measures thread scheduling delay, of which GIL contention is
  the dominant cause in CPython, not a direct GIL instrumentation. Rides
  `runtime_metrics`.
- `RootTraceLogHandler`: a stdlib `logging.Handler` batching records
  (service, level, message, logger, timestamp, active `trace_id`, and
  redacted record extras) and POSTing them to `<api_url>/logs/ingest` on
  the existing flush cadence, from the existing background thread. Caps at
  500 buffered entries (drop-oldest, counted warning) and 8KB messages;
  `emit()` never raises. The resolved endpoint is readable as
  `inst.logs_url`.
- `ROOTTRACE_APM_SERVICE_VERSION` environment fallback for
  `service_version`, so deploy pipelines can report versions (deploy
  markers, regression detection) without code changes.

## 0.2.0 - 2026-07-11

- Automatic database spans (`db_instrumentation=True`, the default):
  MongoDB via a pymongo command listener (motor supported through executor
  context propagation, call `init()` before creating the client),
  Elasticsearch `perform_request`, redis-py (sync and asyncio), asyncpg,
  and SQLAlchemy engine events. Spans are named by operation and target
  (`find app.users`, `SELECT users`, `GET`), never by payload.
- Outbound `aiohttp` instrumentation: the same `http.client.duration`/
  `http.client.requests` metrics, `http` spans, and `traceparent`
  propagation as the stdlib and httpx hooks.
- Database clients that ride an instrumented HTTP transport (async
  Elasticsearch over aiohttp) suppress the inner HTTP span so one query is
  one waterfall row; HTTP metrics still record.
- Kubernetes context reporting: `deployment`/`namespace` init arguments with
  `ROOTTRACE_APM_DEPLOYMENT`/`ROOTTRACE_APM_NAMESPACE` fallbacks, plus
  in-cluster auto-detection from the pod name and the mounted serviceaccount
  namespace.
- Outbound `httpx` instrumentation (sync and async clients), applied when
  httpx is installed: the same `http.client.duration`/`http.client.requests`
  metrics, `http` spans, and `traceparent` propagation as the stdlib hook.
- Request context on trace samples: the WSGI middleware records the origin
  IP (first `X-Forwarded-For` hop, socket peer as `remote_ip`), user agent,
  method, path with query string, and status code of sampled requests, and
  `Transaction.set_http()` lets custom instrumentation attach the same.

## 0.1.0

Initial release.

- Counters, gauges, and timers with tags, aggregated in-process and
  flushed to the RootTrace API on an interval.
- Transactions and spans with per-span-type breakdown metrics.
- Error capture with fingerprinting and stack traces.
- Sampled slow-transaction traces with span waterfalls.
- Outbound HTTP monitoring via stdlib `http.client` instrumentation
  (covers `requests`/`urllib3`/`urllib`), with W3C `traceparent`
  propagation.
- WSGI middleware for inbound request transactions.
- Automatic process runtime metrics (RSS, CPU, GC, threads, uptime).
- Zero dependencies; Python 3.9+.
