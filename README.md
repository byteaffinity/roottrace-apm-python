# roottrace_apm

[![PyPI](https://img.shields.io/pypi/v/roottrace-apm)](https://pypi.org/project/roottrace-apm/)
[![CI](https://github.com/byteaffinity/roottrace-apm-python/actions/workflows/ci.yml/badge.svg)](https://github.com/byteaffinity/roottrace-apm-python/actions/workflows/ci.yml)

RootTrace APM agent for Python. Aggregates counters, gauges, timers,
transactions, spans, and errors in memory and posts one payload per flush
interval to the RootTrace API. Zero dependencies, Python 3.9+.

## Install

```
pip install roottrace-apm
```

## Quickstart

```python
import roottrace_apm as apm

apm.init(
    service="checkout-api",
    token="rtc_...",                        # RootTrace collector token
    api_url="https://api.roottrace.io/api", # the default; point at your own deployment
)
```

Every argument can come from an environment variable instead (see
[Configuration](#configuration)). `init()` fails fast with a `ValueError` on
a missing service/token or a non-http(s) `api_url`; everything after a
successful `init()` never raises into your application.

> **Self-hosted:** the default above is RootTrace Cloud. Point `api_url` (or
> `ROOTTRACE_API_URL` in the service's environment) at your own deployment's
> `/api` base so telemetry never leaves your network.

### Attach a version: it unlocks deploy tracking

Give each release a version and RootTrace marks the deploy on every chart,
compares the new version against the hour before it shipped, and opens an
issue if latency or errors regressed. Without a version, none of that can
happen. Either in code:

```python
apm.init(service="checkout-api", token="rtc_...", service_version="1.4.2")
```

or with no code changes, from your deploy pipeline or Dockerfile:

```dockerfile
ARG BUILD_VERSION
ENV ROOTTRACE_APM_SERVICE_VERSION=${BUILD_VERSION}
```

built with `--build-arg BUILD_VERSION=$(git rev-parse --short HEAD)` (or a
build counter). Versions are capped at 64 characters. A build number or short
git SHA is ideal.

### Metrics

```python
orders = apm.counter("orders.processed")
queue = apm.gauge("queue.depth")
checkout = apm.timer("checkout.duration", tags={"endpoint": "/checkout"})

orders.add()
queue.set(12)

with checkout:
    process_order()

@apm.timed("reports.render.duration")
def render_report():
    ...
```

Metrics flush automatically on a background thread and once more at process
exit. `apm.flush()` forces a synchronous send; `apm.shutdown()` stops the
thread and flushes a final time. The metric name `errors.count` is reserved
for server-side error rollups; recordings under it are dropped with a
warning.

Timers also accumulate a latency histogram between flushes (see
[Histograms](#histograms)).

### Transactions and spans

A transaction is one unit of work (a request, a job run); spans time the
operations inside it. `transaction()` works as a context manager or a
decorator, on both sync and async functions:

```python
with apm.transaction("process-order", type="task"):
    with apm.span("SELECT orders", type="db", subtype="postgresql"):
        rows = fetch_order()
    charge_card()  # outbound HTTP inside a transaction becomes an http span

@apm.transaction("nightly-report", type="task")
async def nightly_report():   # async functions are timed across their awaits
    ...
```

Completed transactions aggregate per `(name, type)` with success/failed
outcome counts and a span breakdown by `(type, subtype)`. An exception
escaping the body marks the transaction failed, captures it as an error, and
re-raises it unchanged. Each flush also carries the two slowest transactions
as full trace samples for the dashboard's waterfall view. Spans opened
without an active transaction are a silent no-op.

### Errors

Escaping exceptions are captured automatically; use `capture_exception` for
ones you handle yourself:

```python
try:
    risky()
except ValueError as exc:
    apm.capture_exception(exc)                 # record, transaction outcome unchanged
    apm.capture_exception(exc, handled=False)  # record and mark the transaction failed
```

Errors group by a stable fingerprint (type + culprit + top stack frames),
at most 50 distinct per flush.

### Histograms

Every timer metric and transaction group carries a `buckets` object
alongside `count`/`sum`/`min`/`max`: a log2 histogram of the durations
observed since the last flush, mapping a bucket index to a count. The
index for a duration `d` in milliseconds is

```
i = min(127, max(0, floor(log2(max(d, 0.001)) * 4) + 40))
```

so 1ms lands in bucket 40, 1000ms in bucket 79, and sub-millisecond
durations clamp toward 0. Four buckets per octave puts each bucket within
about 19% of its neighbours, which is what lets the dashboard compute real
percentiles instead of inferring them from an average. Buckets are additive
and purely optional: a server that ignores the field still reads every
other aggregate exactly as before, and a failed flush merges buckets back
into the live buffer along with the rest.

### Outbound HTTP (requests, urllib3, urllib, httpx, aiohttp)

`init()` instruments the stdlib `http.client` unless you pass
`http_instrumentation=False`. That covers everything built on it with no
extra setup: `requests`, `urllib3` (both 1.x and 2.x), and `urllib`. When
`httpx` or `aiohttp` is installed, their clients are instrumented the same
way (a redirect chain followed by httpx is recorded as one call against the
original destination).
Every outbound call records a `http.client.duration` timer and a
`http.client.requests` counter tagged
`{"destination": "host:port", "status": "2xx"}`; calls that fail without a
response (connection refused, timeout) are recorded with status `error`.
Inside a transaction the call also becomes an `http` span, and a W3C
`traceparent` header is injected so traces connect across services.

### Databases (MongoDB, Elasticsearch, Redis, PostgreSQL, SQLAlchemy)

`init()` also auto-instruments whichever supported database clients are
installed, unless you pass `db_instrumentation=False`. No code changes:
inside a transaction each operation becomes a `db` span named by
operation and target, never by query payload or key. The names look like
`find app.users` (mongodb), `SELECT users` (postgresql/mysql/sqlite via
SQLAlchemy or asyncpg), `GET` (redis), and `POST /idx/_search`
(elasticsearch).

- **MongoDB**: a `pymongo` command listener; works with `motor` too.
  Call `init()` *before* constructing the client: pymongo only applies
  listeners to clients created afterwards.
- **Elasticsearch**: `perform_request` on the sync and async clients.
  The transport's own HTTP call is folded into the db span so one query
  is one waterfall row.
- **Redis**: `redis-py`, sync and asyncio.
- **PostgreSQL**: `asyncpg` connection methods; anything running
  through **SQLAlchemy** (any dialect) is covered via engine events.

### WSGI

```python
from roottrace_apm import WsgiMiddleware

application = WsgiMiddleware(application)
```

Each request records a `http.request.duration` timer and increments a
`http.requests` counter, both tagged `{"method": "GET", "status": "2xx"}`,
and runs inside a transaction named `"<METHOD> <path>"` with id-like path
segments (numbers, UUIDs, hex ids of 16+ chars) collapsed to `:id` (pass
`name_callback=lambda environ: ...` to name it yourself). An incoming
`traceparent` header is adopted, so distributed requests share one trace id.
5xx responses and raised exceptions mark the transaction failed; exceptions
are captured and re-raised.

Sampled requests also carry request context (origin IP, user agent,
method, real path with query string, and status code), shown on the
dashboard's trace view. `client_ip` is the first `X-Forwarded-For` hop
when present (client-controlled, so spoofable unless your edge proxy
overwrites the header); `remote_ip` is always the socket peer the kernel
vouches for. Custom instrumentation can attach the same context to any
transaction:

```python
with apm.transaction("consume orders", type="task") as tx:
    tx.set_http(client_ip=peer, method="GET", path=raw_path, status_code=200)
```

### ASGI (FastAPI, Starlette)

```python
from fastapi import FastAPI
from roottrace_apm import AsgiMiddleware

app = FastAPI()
app.add_middleware(AsgiMiddleware)
```

The same metrics, transactions, trace context, and error capture as the
WSGI middleware, over ASGI 3. Lifespan and websocket scopes pass straight
through untouched.

Transactions are named from the **route template** once the framework has
resolved it: `GET /orders/{order_id}`, not `GET /orders/123`. That is what
keeps transaction cardinality bounded. The name comes from the
matched route the framework publishes on the ASGI scope (`scope["route"]`).

**FastAPI publishes it; plain Starlette does not.** FastAPI's `APIRoute`
puts itself on the scope when it matches, so FastAPI apps get route
templates with no configuration. A plain Starlette `Route` only publishes
`endpoint` and `path_params`, so a plain-Starlette app falls back to the
raw path with parameters left in (`GET /orders/123`), and every distinct
id becomes its own transaction group. With the cap at 250 groups per
flush, an id-heavy Starlette app will churn through it. Name those
transactions yourself until the framework exposes the route:

```python
with apm.transaction(f"GET /orders/{{order_id}}", type="request"):
    ...
```

The same applies to any other ASGI framework that doesn't publish
`scope["route"]`. Check your transaction list for id-shaped names.

The middleware also starts the event-loop lag monitor on the first request
(see below). Wrap the app as the outermost middleware if you want spans
from other middleware to land inside the transaction.

### Event-loop and scheduling lag

Two gauges report where time goes that no span accounts for:

- `python.eventloop.lag_ms`: the mean scheduling drift of the asyncio
  loop since the last flush, sampled by a coroutine that sleeps 500ms and
  measures how late it actually wakes. It's the number that tells you a
  blocking call has snuck into async code. `AsgiMiddleware` starts the
  monitor automatically; for a non-ASGI async app, call
  `apm.watch_event_loop()` from inside the running loop:

  ```python
  async def main():
      apm.watch_event_loop()
      await serve()
  ```

  It's idempotent: repeated calls while the monitor is alive do nothing.

- `process.gil.lag_ms`: the mean oversleep of a daemon thread napping in
  a 100ms loop. Be honest about what this measures: it is **thread
  scheduling delay**, not a direct GIL instrumentation. When the sampler
  thread asks to wake after 100ms and wakes at 140ms, something kept it
  from running. In CPython, GIL contention is the dominant cause of that
  delay (a busy C-extension or a CPU-bound thread holding the lock), but
  OS scheduling pressure, a noisy-neighbour container, and CPU throttling
  land in the same number. Read it as a contention signal to investigate,
  not as proof of a GIL stall.

### Logs

`RootTraceLogHandler` ships stdlib logging records to RootTrace on the same
flush cadence as metrics, over the same token auth:

```python
import logging
from roottrace_apm import RootTraceLogHandler

inst = apm.init(service="checkout-api", token="rtc_...")
logging.getLogger().addHandler(RootTraceLogHandler(inst))
```

Records batch in memory and POST to `<api_url>/logs/ingest` from the
wrapper's existing background thread: no extra thread, no per-record
request. Each entry carries the service, level, message, logger name,
timestamp, and the `trace_id` of the active transaction when there is one,
so a log line links to the trace it came from on the dashboard. A record
logged via `logging.exception(...)` (or any record carrying `exc_info`)
ships with its formatted traceback appended to the message, inside the
8KB cap.

Record extras ride along as `attrs`, with obvious secret-looking keys
(`password`, `token`, `api_key`, `authorization`, `cookie`, ...) replaced
by `[REDACTED]`:

```python
log.info("charged order", extra={"order_id": 7, "api_key": "sk-live-..."})
# -> attrs: {"order_id": 7, "api_key": "[REDACTED]"}
```

That redaction is a coarse safety net keyed on attribute names, not a
guarantee. A secret passed under an innocuous key, or interpolated into
the message itself, still ships. Keep secrets out of log calls.

At most 500 entries buffer between flushes; past that the oldest are
dropped and the count is warned once per flush. Messages truncate at 8KB.
`emit()` never raises into your application, and the wrapper's own
`roottrace_apm` logger is skipped so its warnings can't feed back into
themselves.

## Continuous profiling

Nothing to configure here, deliberately. Profiling is turned on per service in
the RootTrace UI (**Profiling → Settings**); this SDK polls
`GET /api/apm/config` on its background flush loop and starts nothing on its
own. That means turning profiling *off* during the incident it is causing is a
toggle rather than a redeploy.

When enabled, a daemon thread samples `sys._current_frames()` at the configured
rate and uploads a merged profile on each flush.

**This is wall-clock time across every thread, not CPU time**, and it is
labelled `wall` everywhere it appears. True CPU sampling in CPython means
`setitimer(ITIMER_PROF)`, whose signal is only ever delivered to the main
thread: useless in a threaded web server. Wall clock is also frequently the
better answer to "why is my handler slow", because the answer is often that it
was waiting.

Three properties worth knowing:

- **Fails closed.** If the config cannot be fetched, profiling does not start.
- **Bounds are enforced here as well as on the server** (sample rate 10–200Hz
  among others), so a compromised or spoofed control plane cannot spin a
  sampling loop inside your process. Duplicated on purpose.
- **`apm.profiling`** reports whether the sampler is currently running.

Samples are weighted by the period the sampler *achieved*, not the one it was
asked for: under the GIL a sampler competing with a hot loop gets scheduled
late, and at the nominal period every duration in the profile would be
understated by exactly the fraction of ticks that were missed. Measured
overhead (including the sampling itself) is reported on every upload.

## Configuration

Explicit `init()` arguments win over environment variables, which win over
defaults.

| `init()` argument  | Environment variable                                             | Default                       |
| ------------------ | ---------------------------------------------------------------- | ----------------------------- |
| `service`          | `ROOTTRACE_APM_SERVICE`                                          | required                      |
| `token`            | `ROOTTRACE_APM_TOKEN`, falls back to `ROOTTRACE_COLLECTOR_TOKEN` | required                      |
| `api_url`          | `ROOTTRACE_API_URL`                                              | `https://api.roottrace.io/api` |
| `interval_seconds` | `ROOTTRACE_APM_INTERVAL_SECONDS`                                 | 30 (clamped to 5–3600)        |
| `tags`             | n/a                                                              | none (merged into every metric) |
| `runtime_metrics`  | n/a                                                              | enabled                       |
| `service_version`  | `ROOTTRACE_APM_SERVICE_VERSION`                                  | none (reported when set)      |
| `http_instrumentation` | n/a                                                          | enabled                       |
| `deployment`       | `ROOTTRACE_APM_DEPLOYMENT`                                       | auto-detected in Kubernetes (≤253 chars) |
| `namespace`        | `ROOTTRACE_APM_NAMESPACE`                                        | auto-detected in Kubernetes (≤253 chars) |

Inside Kubernetes (`KUBERNETES_SERVICE_HOST` set) the wrapper reports a
`kubernetes` context (deployment, namespace, and pod), deriving the
deployment from the pod name and reading the namespace from the mounted
serviceaccount when not configured explicitly. Outside Kubernetes nothing is
reported unless `deployment`/`namespace` are set. The resolved values are
readable as `inst.deployment` and `inst.namespace`.

The token is the same environment-scoped collector token (`rtc_...`) minted
during collector onboarding.

The instance `init()` returns exposes the resolved endpoint as read-only
properties, for diagnostics and logging:

```python
inst = apm.init(...)
inst.api_url     # e.g. "https://api.roottrace.io/api"
inst.ingest_url  # api_url + "/apm/ingest", the flush target
inst.logs_url    # api_url + "/logs/ingest", the log flush target
```

Runtime metrics reported each flush: `process.memory.rss_bytes`,
`process.cpu.percent`, `process.threads`, `process.gc.collections`,
`process.uptime_seconds`, and `process.gil.lag_ms` (thread scheduling
delay; see [above](#event-loop-and-scheduling-lag)). All of them, and the
`process.gil.lag_ms` sampler thread, are disabled by
`runtime_metrics=False`. `python.eventloop.lag_ms` is reported only once
the event-loop monitor is running.

## Naming your service

Plans cap how many distinct APM services a workspace may have, alongside the
host cap, and `service` is the name that count is taken from.

- Every replica of one deployment must pass the **same** `service`. It is the
  logical service, not the instance. Appending a pod name or a hostname turns
  one service into as many services as you have replicas.
- The same `service` in staging and in production counts once, so environment
  belongs in the collector token's environment, not in the name.

A service counts while it is reporting and stops counting seven days after its
last flush, so a decommissioned service releases its slot on its own. Ingest
from a service that is already reporting is never refused. A workspace at its
cap refuses only the first flush from a new service name, with HTTP 402 and
`"limit_type": "services"` in the body.

## Development

```
git clone https://github.com/byteaffinity/roottrace-apm-python
cd roottrace-apm-python
python3 -m unittest discover     # tests (no install needed)
python3 -m ruff check .          # lint
```

The package lives under `src/`. Run the examples against the checkout with
`PYTHONPATH=src python3 examples/demo.py`, or `pip install -e .` first.

## License

Apache-2.0. See [LICENSE](LICENSE).
