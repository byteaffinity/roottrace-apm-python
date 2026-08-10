"""RootTrace APM wrapper for Python.

Aggregates counters, gauges, and timers in memory and posts one ingest
payload per flush interval to the RootTrace API. Stdlib only.
"""

from __future__ import annotations

import asyncio
import atexit
import contextvars
import datetime
import functools
import gc
import hashlib
import http.client
import inspect
import json
import logging
import math
import os
import platform
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

try:
    import resource
except ImportError:  # not available on Windows
    resource = None

VERSION = "0.4.5"
DEFAULT_API_URL = "https://api.roottrace.io/api"
MAX_ENTRIES = 500  # wire cap per ingest request
MAX_USER_ENTRIES = MAX_ENTRIES - 8  # headroom so runtime metrics fit under the cap
MAX_TAG_KEYS = 8
MAX_NAME_LENGTH = 200
MAX_TX_GROUPS = 250  # transaction groups per flush (PROTOCOL.md)
MAX_TX_BREAKDOWN_ROWS = 40  # span-breakdown rows per transaction group
MAX_TX_TYPE_LENGTH = 40
MAX_SUBTYPE_LENGTH = 200
MAX_ERRORS = 50  # distinct error fingerprints per flush
MAX_MESSAGE_LENGTH = 1000
MAX_CULPRIT_LENGTH = 300
MAX_STACK_FRAMES = 50
MAX_ERROR_TYPE_LENGTH = 200
MAX_FRAME_FUNCTION_LENGTH = 300
MAX_FRAME_FILE_LENGTH = 1024
MAX_SERVICE_VERSION_LENGTH = 64
MAX_K8S_NAME_LENGTH = 253  # DNS-1123 cap on Kubernetes names (PROTOCOL.md)
K8S_NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
RESERVED_METRIC_NAME = "errors.count"  # the server folds error rollups into this name
MAX_TRACE_SAMPLES = 2  # slowest transactions kept per flush
MAX_SAMPLE_SPANS = 100  # spans kept on one trace sample
MAX_HTTP_PATH_LENGTH = 1024  # http context on trace samples (PROTOCOL.md)
MAX_HTTP_USER_AGENT_LENGTH = 300
MAX_HTTP_IP_LENGTH = 64  # fits IPv6 with a zone id
MAX_HISTOGRAM_BUCKET = 127  # shared histogram contract: bucket indexes 0-127
MAX_LOG_ENTRIES = 500  # log records buffered between flushes
MAX_LOG_MESSAGE_LENGTH = 8192  # 8KB message truncation

# --- Continuous profiling --------------------------------------------------
#
# Off unless the server says otherwise. Profiling runs inside a customer's
# process, so the switch lives in the RootTrace UI where somebody can reach it
# during the incident it is causing -- not in an environment variable that
# needs a redeploy to change.
PROFILE_CONFIG_INTERVAL_SECONDS = 60  # how often to re-ask what to do
PROFILE_MAX_FRAMES = 128
PROFILE_MAX_STACKS = 5000  # distinct stacks kept per flush

# --- Security sinks --------------------------------------------------------
# Call sites an attacker needs and ordinary request handling rarely reaches.
# Reporting the *fact* costs a dictionary; reporting the arguments would mean
# shipping whatever the attacker passed, so only the shape is recorded.
SECURITY_MAX_EVENTS = 100  # buffered between flushes, then dropped
SECURITY_MAX_TARGET = 512
# Every bound the server enforces, enforced here again. Trusting the server to
# bound this would turn a compromised or spoofed control plane into an
# application-level DoS inside every process running the SDK. It costs four
# lines, so there is no argument for leaving it out.
PROFILE_BOUNDS = {
    "sample_rate_hz": (10, 200),
    "upload_interval_seconds": (15, 900),
    "max_frames": (16, PROFILE_MAX_FRAMES),
    "max_stacks": (500, PROFILE_MAX_STACKS),
}

logger = logging.getLogger("roottrace_apm")

__all__ = [
    "Apm", "Counter", "Gauge", "Timer", "Span", "WsgiMiddleware",
    "AsgiMiddleware", "RootTraceLogHandler",
    "init", "counter", "gauge", "timer", "timed", "transaction", "span",
    "capture_exception", "flush", "shutdown", "watch_event_loop",
    "VERSION",
]

# The active transaction. Contextvars isolate threads and asyncio tasks, so
# spans started while a transaction is open attach to the right one.
_active_transaction = contextvars.ContextVar("roottrace_apm_transaction", default=None)

# Open Timer/Span starts, per context. Tuples, never mutated in place: each
# push/pop set()s a new tuple, so interleaved asyncio tasks on one thread
# can't pop each other's starts (a task's set() only affects its own context).
_timer_starts = contextvars.ContextVar("roottrace_apm_timer_starts", default=())
_span_starts = contextvars.ContextVar("roottrace_apm_span_starts", default=())

# True while a database client (Elasticsearch, ...) is inside its own
# instrumented call: the HTTP hooks then skip their span so one logical
# operation doesn't show up twice in the waterfall. Metrics still record.
_span_suppressed = contextvars.ContextVar("roottrace_apm_span_suppressed", default=False)


def _stack_push(var, entry):
    var.set(var.get() + (entry,))


def _stack_pop(var, owner):
    """Remove and return the newest entry owned by `owner`, else None."""
    stack = var.get()
    for i in range(len(stack) - 1, -1, -1):
        if stack[i][0] is owner:
            var.set(stack[:i] + stack[i + 1:])
            return stack[i]
    return None


def _current_transaction():
    """The active transaction, treating an already-closed one as absent."""
    tx = _active_transaction.get()
    if tx is None or tx.closed:
        return None
    return tx


# Set while _send posts to the API, so the http.client instrumentation
# never measures the wrapper's own flush traffic.
_self_calls = threading.local()

_security_events = []
_security_lock = threading.Lock()


def _report_sink(kind, target):
    """Record that a dangerous call site was reached.

    Silent and total: this runs inside somebody's request handler, so it never
    raises, never blocks, and never touches the network -- the flush thread
    ships what it leaves behind.

    The transaction is what makes the report worth anything. Without it there
    is a fact with no actor; with it the server can name the request, the
    endpoint and the address that reached the sink.
    """
    try:
        tx = _current_transaction()
        http_context = (tx.http or {}) if tx is not None else {}
        event = {
            "kind": kind,
            "target": str(target)[:SECURITY_MAX_TARGET],
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "trace_id": getattr(tx, "trace_id", None),
            "transaction": getattr(tx, "name", None),
            "method": http_context.get("method"),
            "path": http_context.get("path"),
        }
        with _security_lock:
            # Drop rather than grow. A process being driven by an attacker
            # produces these faster than any flush interval, and an unbounded
            # buffer inside the victim is its own denial of service.
            if len(_security_events) < SECURITY_MAX_EVENTS:
                _security_events.append(event)
    except Exception:
        pass


_security_patched = False


def _instrument_security_sinks():
    """Wrap process spawn and pickle loading. Idempotent, and never fatal.

    DELIBERATELY NARROW. eval/exec and open() would catch more, and patching
    builtins would reach into every library in the process to do it -- for a
    wrapper whose first promise is that it cannot break the application, that
    trade is not worth making. subprocess and pickle are attributes on their
    own modules, so wrapping them touches nothing else.
    """
    global _security_patched
    if _security_patched:
        return
    try:
        import subprocess

        original_popen_init = subprocess.Popen.__init__

        @functools.wraps(original_popen_init)
        def popen_init(self, args, *rest, **kwargs):
            # The executable, never the arguments: an attacker's argv is the
            # payload, and this file does not collect payloads.
            try:
                if isinstance(args, (list, tuple)) and args:
                    target = str(args[0])
                else:
                    target = str(args).split()[0] if args else "?"
                _report_sink("process_spawn", target)
            except Exception:
                pass
            return original_popen_init(self, args, *rest, **kwargs)

        subprocess.Popen.__init__ = popen_init

        original_system = os.system

        @functools.wraps(original_system)
        def system(command):
            _report_sink("process_spawn", str(command).split()[0] if command else "?")
            return original_system(command)

        os.system = system
    except Exception:
        logger.debug("could not instrument process spawning", exc_info=True)

    try:
        import pickle

        original_loads = pickle.loads

        @functools.wraps(original_loads)
        def loads(data, *rest, **kwargs):
            _report_sink("deserialization", "pickle.loads")
            return original_loads(data, *rest, **kwargs)

        pickle.loads = loads
    except Exception:
        logger.debug("could not instrument deserialization", exc_info=True)

    _security_patched = True

# W3C traceparent: 2-hex version, 32-hex trace id, 16-hex parent id, 2-hex
# flags. Future versions (anything but ff) may append "-suffix" fields.
_TRACEPARENT_RE = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}(-.*)?$", re.IGNORECASE
)


def _parse_traceparent(value):
    """Return the trace id from a valid traceparent header, else None."""
    if not isinstance(value, str):
        return None
    match = _TRACEPARENT_RE.match(value.strip())
    if match is None:
        return None
    version, trace_id, parent_id, suffix = match.groups()
    version = version.lower()
    if version == "ff":  # forbidden per W3C
        return None
    if version == "00" and suffix:  # version 00 has exactly four fields
        return None
    trace_id = trace_id.lower()
    if trace_id == "0" * 32 or parent_id.lower() == "0" * 16:  # all-zero ids are invalid
        return None
    return trace_id


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


# Deployment pods look like <name>-<replicaset-hash>-<suffix>; StatefulSet
# pods look like <name>-<ordinal>. Names matching neither are sent as-is.
_K8S_DEPLOYMENT_POD_RE = re.compile(r"^(.+)-[a-z0-9]{5,10}-[a-z0-9]{5}$")
_K8S_STATEFULSET_POD_RE = re.compile(r"^(.+)-\d+$")


def _sanitize_k8s_name(value):
    """Coerce, trim, and truncate one Kubernetes name; None when empty."""
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    if len(value) > MAX_K8S_NAME_LENGTH:
        logger.warning("kubernetes name %r longer than %d chars; truncating",
                       value, MAX_K8S_NAME_LENGTH)
        value = value[:MAX_K8S_NAME_LENGTH]
    return value


def _deployment_from_pod(pod):
    match = _K8S_DEPLOYMENT_POD_RE.match(pod) or _K8S_STATEFULSET_POD_RE.match(pod)
    return match.group(1) if match else pod


def _bucket_index(duration_ms):
    """Histogram bucket for a duration, per the shared wrapper contract.

    i = min(127, max(0, floor(log2(max(d, 0.001)) * 4) + 40)), so 1ms -> 40,
    1000ms -> 79, and sub-millisecond durations clamp toward 0."""
    return min(MAX_HISTOGRAM_BUCKET,
               max(0, math.floor(math.log2(max(duration_ms, 0.001)) * 4) + 40))


def _merge_buckets(into, source):
    for index, count in source.items():
        into[index] = into.get(index, 0) + count


def _tags_key(tags):
    # Canonical k=v,k=v form (PROTOCOL.md): percent-encode %, =, and , in
    # keys and values so distinct tag maps never collide. '%' goes first.
    def esc(s):
        return s.replace("%", "%25").replace("=", "%3D").replace(",", "%2C")
    return ",".join(f"{esc(k)}={esc(v)}" for k, v in sorted(tags.items()))


class _HttpStatusError(RuntimeError):
    """HTTP error response from the ingest endpoint, with its status code."""

    def __init__(self, code, detail, retry_after=None):
        super().__init__(f"RootTrace API returned HTTP {code}: {detail}")
        self.code = code
        self.retry_after = retry_after


class _UnserializableError(ValueError):
    """json.dumps refused the payload; retrying it can never succeed."""


def _clamp_profile_settings(raw):
    """Force a server-supplied profiling config into ranges this SDK accepts.

    Independent of the server's own clamping, on purpose. See PROFILE_BOUNDS.
    """
    config = dict(raw or {})
    result = {"profiling_enabled": bool(config.get("profiling_enabled"))}
    defaults = {"sample_rate_hz": 100, "upload_interval_seconds": 60,
                "max_frames": PROFILE_MAX_FRAMES, "max_stacks": PROFILE_MAX_STACKS}
    for key, (low, high) in PROFILE_BOUNDS.items():
        try:
            value = int(config.get(key, defaults[key]))
        except (TypeError, ValueError):
            value = defaults[key]
        result[key] = max(low, min(high, value))
    return result


def _frame_name(code):
    """A frame's identity: module and function, deliberately without a line.

    A line number would give a function a new identity every time an edit
    shifted it down, which would break diffing a flamegraph across a deploy --
    the one thing this is for. A function that got slower should read as the
    same function, slower.
    """
    module = os.path.basename(code.co_filename).removesuffix(".py")
    name = code.co_name
    return f"{module}.{name}" if name != "<module>" else module


class _Profiler:
    """A wall-clock sampling profiler over every thread. Stdlib only.

    WALL-CLOCK, AND SAID SO EVERYWHERE
    ----------------------------------
    This measures where threads *are*, which includes time blocked on a socket
    or a lock. It is not CPU time. True CPU sampling in CPython means
    ``setitimer(ITIMER_PROF)``, whose signal is only ever delivered to the main
    thread -- useless for the threaded web servers this SDK mostly runs in. So
    the honest measurement is the one taken, and every label it produces says
    ``wall``. Wall-clock is also the better answer to "why is my handler slow",
    since the answer is frequently that it was waiting.

    Sampling is a daemon thread reading ``sys._current_frames()``: one dict of
    every thread's current frame, cheap enough to take a hundred times a second
    and the only way to see threads that are not running the sampler.
    """

    def __init__(self, apm, settings):
        self._apm = apm
        self._settings = settings
        self._counts = {}  # frames tuple -> sample count
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._own_thread_id = None
        self._dropped = 0  # samples discarded once max_stacks was reached
        self._busy_seconds = 0.0  # time spent inside the sampler itself
        self._rounds = 0  # sampling passes actually taken
        self._started_at = time.monotonic()

    @property
    def period_ns(self):
        return int(1e9 / self._settings["sample_rate_hz"])

    def start(self):
        self._thread = threading.Thread(
            target=self._loop, name="roottrace_apm-profiler", daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        self._own_thread_id = threading.get_ident()
        interval = 1.0 / self._settings["sample_rate_hz"]
        # An absolute schedule rather than sleep(interval): the latter drifts by
        # however long each sample took, so a busy process would silently
        # sample slower than it claims and every duration would be understated.
        next_at = time.monotonic() + interval
        while not self._stop.wait(max(0.0, next_at - time.monotonic())):
            started = time.monotonic()
            try:
                self._sample()
            except Exception:
                logger.debug("profiler sample failed", exc_info=True)
            self._busy_seconds += time.monotonic() - started
            # Skip missed ticks outright instead of trying to catch up, which
            # under load would spin the sampler at full speed.
            now = time.monotonic()
            next_at += interval
            if next_at < now:
                next_at = now + interval

    def _sample(self):
        self._rounds += 1
        max_frames = self._settings["max_frames"]
        max_stacks = self._settings["max_stacks"]
        frames_by_thread = sys._current_frames()
        for thread_id, frame in frames_by_thread.items():
            if thread_id == self._own_thread_id:
                continue  # the profiler profiling itself is pure noise
            stack = []
            while frame is not None and len(stack) < max_frames:
                stack.append(_frame_name(frame.f_code))
                frame = frame.f_back
            if not stack:
                continue
            stack.reverse()  # f_back walks leaf to root; graphs are drawn root-first
            key = tuple(stack)
            with self._lock:
                if key in self._counts:
                    self._counts[key] += 1
                elif len(self._counts) < max_stacks:
                    self._counts[key] = 1
                else:
                    self._dropped += 1

    def drain(self):
        """The profile since the last drain, or None if nothing was sampled."""
        with self._lock:
            counts, self._counts = self._counts, {}
            dropped, self._dropped = self._dropped, 0
            busy, self._busy_seconds = self._busy_seconds, 0.0
            rounds, self._rounds = self._rounds, 0
        elapsed = time.monotonic() - self._started_at
        self._started_at = time.monotonic()
        if not counts or not rounds:
            return None
        if dropped:
            logger.warning("profiler dropped %d samples: more than %d distinct stacks",
                           dropped, self._settings["max_stacks"])
        # Each sample is weighted by the period the sampler ACHIEVED, not the
        # one it asked for. Under the GIL a sampler competing with a hot loop
        # gets scheduled late and takes fewer passes than the rate implies; at
        # the nominal period that understates every duration in the profile by
        # exactly the fraction of ticks that were missed. Dividing the elapsed
        # window by the passes actually taken makes the totals add up to the
        # window regardless of how badly the sampler was starved.
        period = (elapsed * 1e9) / rounds
        stacks = [{"frames": list(frames), "value": count * period}
                  for frames, count in counts.items()]
        return {
            "profile_type": "wall",
            "value_unit": "nanoseconds",
            "period_ms": period / 1e6,
            "duration_ms": elapsed * 1000.0,
            "sample_count": rounds,
            "stacks": stacks,
            # Measured, not asserted. A profiler that claims an overhead it has
            # never checked is asking to be trusted on the one number the
            # customer cares about most.
            "overhead_percent": round(100.0 * busy / elapsed, 3) if elapsed > 0 else 0.0,
        }


class Apm:
    """Aggregation buffer plus the background flush loop."""

    def __init__(self, service, token, api_url=DEFAULT_API_URL, interval_seconds=30,
                 tags=None, runtime_metrics=True, service_version=None,
                 deployment=None, namespace=None, commit_sha=None):
        self.service = service
        self.token = token
        self._api_url = api_url.rstrip("/")
        self.interval_seconds = interval_seconds
        self.tags = {str(k): str(v) for k, v in (tags or {}).items()}
        if len(self.tags) > MAX_TAG_KEYS:
            # trimmed once here: runtime metrics bypass the per-record trim
            logger.warning("instance tags have %d keys; keeping the first %d in sorted order",
                           len(self.tags), MAX_TAG_KEYS)
            self.tags = {k: self.tags[k] for k in sorted(self.tags)[:MAX_TAG_KEYS]}
        self.runtime_metrics = runtime_metrics
        self.service_version = service_version
        self.commit_sha = commit_sha
        self.hostname = socket.gethostname()
        self._kubernetes = self._detect_kubernetes(deployment, namespace)
        self._buffer = {}
        self._tx_buffer = {}  # (name, type) -> transaction group
        self._error_buffer = {}  # fingerprint -> error entry
        self._trace_samples = []  # up to MAX_TRACE_SAMPLES, slowest win
        self._log_buffer = []  # RootTraceLogHandler entries, cap MAX_LOG_ENTRIES
        self._logs_dropped = 0  # drop-oldest count since the last flush
        self._loop_monitor = None  # asyncio task measuring event-loop lag
        self._loop_lag = (0.0, 0)  # (drift sum ms, samples) since last flush
        self._gil_lag = (0.0, 0)  # same, from the sampler thread
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._warned = set()
        self._retry_at = 0.0  # monotonic deadline set by HTTP 429 Retry-After
        self._ssl_context = ssl.create_default_context()
        self._started = time.monotonic()
        self._profiler = None  # set only once the server says profiling is on
        self._profile_config = None
        # -inf, not 0: time.monotonic() is uptime on Linux, so a process that
        # starts in a freshly booted container reads a clock still in single
        # digits. Against 0 the "has the interval elapsed" guard would suppress
        # the very first config fetch until the *host* reached 60 seconds --
        # profiling silently off for a minute on exactly the machines that
        # restart most.
        self._profile_config_at = float("-inf")
        # Set when a profiler starts, so the first upload covers a full
        # configured window rather than whatever fraction of one happened to
        # elapse before the next metric flush.
        self._profile_upload_at = 0.0
        t = os.times()
        self._cpu_sample = (t.user + t.system, self._started)
        self._gc_total = sum(s.get("collections", 0) for s in gc.get_stats())

    @property
    def api_url(self):
        """The resolved RootTrace API base URL. Read-only."""
        return self._api_url

    @property
    def ingest_url(self):
        """The full flush target, <api_url>/apm/ingest. Read-only."""
        return self._api_url + "/apm/ingest"

    @property
    def logs_url(self):
        """The log flush target, <api_url>/logs/ingest. Read-only."""
        return self._api_url + "/logs/ingest"

    @property
    def profiles_url(self):
        """The profile upload target, <api_url>/apm/profiles. Read-only."""
        return self._api_url + "/apm/profiles"

    @property
    def security_url(self):
        """Where sink reports go, <api_url>/apm/security-events. Read-only."""
        return self._api_url + "/apm/security-events"

    @property
    def config_url(self):
        """Where the SDK asks what it should be doing. Read-only."""
        return (self._api_url + "/apm/config?service="
                + urllib.parse.quote(self.service, safe=""))

    @property
    def profiling(self):
        """True while the sampler is running. Read-only; the server decides."""
        return self._profiler is not None

    @property
    def deployment(self):
        """The resolved Kubernetes deployment name, or None. Read-only."""
        return self._kubernetes.get("deployment") if self._kubernetes else None

    @property
    def namespace(self):
        """The resolved Kubernetes namespace, or None. Read-only."""
        return self._kubernetes.get("namespace") if self._kubernetes else None

    def _detect_kubernetes(self, deployment, namespace):
        """Resolve the Kubernetes context once at init; None outside a cluster.

        Explicit values (init arguments, then the ROOTTRACE_APM_DEPLOYMENT /
        ROOTTRACE_APM_NAMESPACE env vars) win; in-cluster auto-detection only
        fills the gaps, and only when KUBERNETES_SERVICE_HOST says the process
        runs inside a cluster. Never raises.
        """
        deployment = _sanitize_k8s_name(deployment) or _sanitize_k8s_name(
            env("ROOTTRACE_APM_DEPLOYMENT") or None)
        namespace = _sanitize_k8s_name(namespace) or _sanitize_k8s_name(
            env("ROOTTRACE_APM_NAMESPACE") or None)
        in_cluster = bool(env("KUBERNETES_SERVICE_HOST"))
        pod = _sanitize_k8s_name(self.hostname)
        if in_cluster:
            if deployment is None and pod:
                deployment = _deployment_from_pod(pod)
            if namespace is None:
                try:
                    with open(K8S_NAMESPACE_FILE, encoding="utf-8") as f:
                        namespace = _sanitize_k8s_name(f.read())
                except OSError:
                    pass  # not readable; the namespace stays unknown
        if not in_cluster and deployment is None and namespace is None:
            return None  # the payload omits the kubernetes object entirely
        kubernetes = {}
        if deployment:
            kubernetes["deployment"] = deployment
        if namespace:
            kubernetes["namespace"] = namespace
        if pod:  # sent whenever the kubernetes object is: it's the hostname
            kubernetes["pod"] = pod
        return kubernetes or None

    def _start(self):
        self._thread = threading.Thread(
            target=self._loop, name="roottrace_apm-flush", daemon=True
        )
        self._thread.start()
        if self.runtime_metrics:
            threading.Thread(
                target=self._gil_loop, name="roottrace_apm-gil", daemon=True
            ).start()

    def _loop(self):
        while not self._stop.wait(self.interval_seconds):
            try:
                self._refresh_profile_config()
            except Exception:
                logger.debug("profiling config refresh failed", exc_info=True)
            try:
                self.flush()
            except Exception:
                # flush handles send errors itself; this keeps the loop alive
                logger.exception("background flush failed")

    def _refresh_profile_config(self):
        """Ask the server whether to profile, and start or stop accordingly.

        FAILS CLOSED. If the config cannot be fetched -- network, auth, a
        malformed response -- profiling does not start, and a running profiler
        keeps the settings it already has rather than being torn down for a
        transient blip. An SDK that defaults to *on* when the control plane is
        unreachable is the wrong failure direction for code that runs inside
        somebody else's process.
        """
        now = time.monotonic()
        if now - self._profile_config_at < PROFILE_CONFIG_INTERVAL_SECONDS:
            return
        self._profile_config_at = now
        try:
            fetched = self._get(self.config_url)
        except Exception as exc:
            if self._profiler is None:
                self._warn_throttled(
                    "profile_config",
                    "profiling stays off: config could not be fetched from %s: %s",
                    self.config_url, exc)
            return
        config = _clamp_profile_settings(fetched)
        self._profile_config = config
        if not config["profiling_enabled"]:
            if self._profiler is not None:
                logger.info("profiling turned off from the RootTrace UI")
                self._profiler.stop()
                self._profiler = None
            return
        if self._profiler is not None:
            if self._profiler._settings == config:
                return
            # A rate change restarts the sampler: a running loop's interval is
            # baked into its schedule, and mutating it underneath would leave
            # already-counted samples weighted by the old period.
            logger.info("profiling settings changed; restarting the sampler")
            self._profiler.stop()
            self._profiler = None
        logger.info("profiling on: wall-clock at %dHz", config["sample_rate_hz"])
        self._profiler = _Profiler(self, config)
        self._profiler.start()
        self._profile_upload_at = time.monotonic()

    def _flush_security_events(self):
        """Post whatever the sinks recorded since the last flush.

        Dropped rather than retried on failure, like profiles: these are small
        and a retry queue inside a process that may already be compromised is
        the wrong place to hold evidence. The server keeps what arrives.
        """
        with _security_lock:
            if not _security_events:
                return
            events = _security_events[:]
            del _security_events[:]
        payload = {
            "service": self.service,
            "service_version": self.service_version,
            "deployment": self.deployment or (self.commit_sha or None),
            "events": events,
        }
        try:
            self._post(self.security_url, payload)
        except Exception as exc:
            self._warn_throttled(
                "security_events",
                "dropping %d security events: upload to %s failed: %s",
                len(events), self.security_url, exc)

    def _flush_profile(self):
        if self._profiler is None:
            return
        # One upload per configured interval, not per metric flush: the metric
        # cadence defaults to 30s and can be set as low as 5s, which would cut
        # every profile into slivers and ignore upload_interval_seconds
        # entirely -- a setting the RootTrace UI offers and the server clamps.
        interval = (self._profile_config or {}).get("upload_interval_seconds", 60)
        now = time.monotonic()
        if now - self._profile_upload_at < interval:
            return
        self._profile_upload_at = now
        profile = self._profiler.drain()
        if not profile:
            return
        payload = {
            "service": self.service,
            "service_version": self.service_version,
            "deployment": self.deployment or (self.commit_sha or None),
            **profile,
        }
        try:
            self._post(self.profiles_url, payload)
        except Exception as exc:
            # Profiles are dropped rather than retried. They are large, they
            # are statistical, and a lost five minutes leaves a slightly
            # thinner flamegraph -- which is a far better outcome than a retry
            # queue growing inside the customer's process.
            self._warn_throttled("profile_upload", "dropping a profile: upload to %s failed: %s",
                                 self.profiles_url, exc)

    def watch_event_loop(self):
        """Start the event-loop lag monitor on the running loop.

        Reports the mean scheduling drift since the last flush as the
        `python.eventloop.lag_ms` gauge. Started automatically by
        AsgiMiddleware on the first request; call it yourself from loop
        code to monitor a non-ASGI app. Idempotent while the monitor is
        alive; a no-op (with a warning) outside a running loop. Never
        raises."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._warn_throttled("eventloop-monitor",
                                 "watch_event_loop() needs a running event loop; not started")
            return
        try:
            with self._lock:
                if self._loop_monitor is not None and not self._loop_monitor.done():
                    return
                self._loop_monitor = loop.create_task(self._monitor_event_loop())
        except Exception:
            logger.exception("failed to start the event-loop lag monitor")

    async def _monitor_event_loop(self):
        loop = asyncio.get_running_loop()
        while not self._stop.is_set():
            before = loop.time()
            await asyncio.sleep(0.5)
            drift = max((loop.time() - before - 0.5) * 1000.0, 0.0)
            with self._lock:
                total, count = self._loop_lag
                self._loop_lag = (total + drift, count + 1)

    def _gil_loop(self):
        # Oversleep of a 100ms nap = how long this thread waited to be
        # rescheduled; in CPython that's dominated by GIL contention.
        while not self._stop.is_set():
            start = time.perf_counter()
            time.sleep(0.1)
            drift = max((time.perf_counter() - start - 0.1) * 1000.0, 0.0)
            with self._lock:
                total, count = self._gil_lag
                self._gil_lag = (total + drift, count + 1)

    def _record_lag_gauges(self, snapshot):
        # Independent of runtime_metrics: the monitors only run when someone
        # started them, and their samples must not survive into the next flush.
        try:
            with self._lock:
                loop_lag, self._loop_lag = self._loop_lag, (0.0, 0)
                gil_lag, self._gil_lag = self._gil_lag, (0.0, 0)
            if loop_lag[1]:
                self._snapshot_record(snapshot, "python.eventloop.lag_ms", "gauge",
                                      "ms", loop_lag[0] / loop_lag[1])
            if gil_lag[1]:
                self._snapshot_record(snapshot, "process.gil.lag_ms", "gauge",
                                      "ms", gil_lag[0] / gil_lag[1])
        except Exception:
            logger.exception("lag gauge collection failed")

    def _record_log(self, entry):
        # Called from RootTraceLogHandler.emit; must never raise.
        try:
            dropped = False
            with self._lock:
                if len(self._log_buffer) >= MAX_LOG_ENTRIES:
                    self._log_buffer.pop(0)
                    self._logs_dropped += 1
                    dropped = True
                self._log_buffer.append(entry)
            if dropped:  # warned outside the lock: the warning may re-enter emit()
                self._warn_throttled(
                    "log-cap",
                    "log buffer full at %d entries; dropping the oldest",
                    MAX_LOG_ENTRIES,
                )
        except Exception:
            logger.exception("failed to buffer log record")

    def _warn_throttled(self, key, msg, *args):
        # At most one warning per key per flush interval; flush clears the set.
        if key in self._warned:
            return
        self._warned.add(key)
        logger.warning(msg, *args)

    def _record(self, name, kind, tags, unit, value):
        # Guarded end to end: instrumentation must never raise into the app.
        try:
            try:
                value = float(value)
            except (TypeError, ValueError):
                logger.warning("ignoring non-numeric value %r for %s %r", value, kind, name)
                return
            if not math.isfinite(value):
                self._warn_throttled(("non-finite", name),
                                     "ignoring non-finite value %r for %s %r", value, kind, name)
                return
            if not name:
                self._warn_throttled("name-empty",
                                     "ignoring %s recording with empty metric name", kind)
                return
            if not isinstance(name, str):  # a bytes name would poison the whole payload
                name = str(name)
            if unit is not None and not isinstance(unit, str):
                unit = str(unit)
            if name == RESERVED_METRIC_NAME:
                self._warn_throttled("name-reserved",
                                     "metric name %r is reserved for server-side error rollups; "
                                     "dropping", name)
                return
            if len(name) > MAX_NAME_LENGTH:
                self._warn_throttled(("name-length", name[:MAX_NAME_LENGTH]),
                                     "metric name %r longer than %d chars; truncating",
                                     name, MAX_NAME_LENGTH)
                name = name[:MAX_NAME_LENGTH]
            merged = dict(self.tags)
            for k, v in (tags or {}).items():
                merged[str(k)] = str(v)
            if len(merged) > MAX_TAG_KEYS:
                self._warn_throttled(("tag-keys", name),
                                     "metric %r has %d tag keys; keeping the first %d in sorted order",
                                     name, len(merged), MAX_TAG_KEYS)
                merged = {k: merged[k] for k in sorted(merged)[:MAX_TAG_KEYS]}
            key = (name, _tags_key(merged))
            with self._lock:
                entry = self._buffer.get(key)
                if entry is None:
                    if len(self._buffer) >= MAX_USER_ENTRIES:
                        self._warn_throttled(
                            "entry-cap",
                            "metric buffer full at %d entries; dropping new series until next flush",
                            MAX_USER_ENTRIES,
                        )
                        return
                    entry = {"name": name, "kind": kind, "unit": unit, "tags": merged}
                    if kind == "counter":
                        entry.update(count=0, sum=0.0)
                    elif kind == "timer":
                        entry.update(count=0, sum=0.0, min=value, max=value, buckets={})
                    self._buffer[key] = entry
                if entry["kind"] != kind:
                    logger.warning("metric %r is a %s; ignoring %s recording",
                                   name, entry["kind"], kind)
                    return
                if kind == "counter":
                    entry["count"] += 1
                    entry["sum"] += value
                elif kind == "timer":
                    entry["count"] += 1
                    entry["sum"] += value
                    entry["min"] = min(entry["min"], value)
                    entry["max"] = max(entry["max"], value)
                    bucket = _bucket_index(value)
                    entry["buckets"][bucket] = entry["buckets"].get(bucket, 0) + 1
                else:
                    entry["value"] = value
        except Exception:
            logger.exception("failed to record metric %r", name)

    def _record_transaction(self, tx, duration_ms, outcome):
        # Guarded end to end: instrumentation must never raise into the app.
        try:
            started_at = datetime.datetime.fromtimestamp(
                tx.started_at, datetime.timezone.utc
            ).isoformat()
            with self._lock:
                # Trace-sample competition first: the slowest transactions win
                # a slot even when their group is dropped at the cap below.
                samples = self._trace_samples
                if (len(samples) < MAX_TRACE_SAMPLES
                        or duration_ms > min(s["duration_ms"] for s in samples)):
                    if len(samples) >= MAX_TRACE_SAMPLES:
                        samples.remove(min(samples, key=lambda s: s["duration_ms"]))
                    sample = {
                        "trace_id": tx.trace_id,
                        "transaction_name": tx.name,
                        "transaction_type": tx.type,
                        "duration_ms": duration_ms,
                        "started_at": started_at,
                        "outcome": outcome,
                        "spans_dropped": tx.spans_dropped,
                        "spans": list(tx.spans),
                    }
                    if tx.http:
                        sample["http"] = dict(tx.http)
                    samples.append(sample)
                key = (tx.name, tx.type)
                group = self._tx_buffer.get(key)
                if group is None:
                    if len(self._tx_buffer) >= MAX_TX_GROUPS:
                        self._warn_throttled(
                            "tx-cap",
                            "transaction buffer full at %d groups; dropping new ones until next flush",
                            MAX_TX_GROUPS,
                        )
                        return
                    group = {"name": tx.name, "type": tx.type,
                             "count": 0, "sum": 0.0,
                             "min": duration_ms, "max": duration_ms,
                             "success": 0, "failed": 0, "spans": {}, "buckets": {}}
                    self._tx_buffer[key] = group
                group["count"] += 1
                group["sum"] += duration_ms
                group["min"] = min(group["min"], duration_ms)
                group["max"] = max(group["max"], duration_ms)
                bucket = _bucket_index(duration_ms)
                group["buckets"][bucket] = group["buckets"].get(bucket, 0) + 1
                group[outcome] += 1
                for span_key, row in tx.breakdown.items():
                    existing = group["spans"].get(span_key)
                    if existing is None:
                        if len(group["spans"]) >= MAX_TX_BREAKDOWN_ROWS:
                            self._warn_throttled(
                                ("tx-breakdown", tx.name),
                                "transaction %r has more than %d span breakdown rows; dropping the rest",
                                tx.name, MAX_TX_BREAKDOWN_ROWS,
                            )
                            continue
                        group["spans"][span_key] = existing = {"count": 0, "sum": 0.0}
                    existing["count"] += row["count"]
                    existing["sum"] += row["sum"]
        except Exception:
            logger.exception("failed to record transaction %r", tx.name)

    def _record_error(self, error):
        # Guarded end to end: error capture must never raise into the app.
        try:
            with self._lock:
                entry = self._error_buffer.get(error["fingerprint"])
                if entry is None:
                    if len(self._error_buffer) >= MAX_ERRORS:
                        self._warn_throttled(
                            "error-cap",
                            "error buffer full at %d distinct errors; dropping new ones until next flush",
                            MAX_ERRORS,
                        )
                        return
                    self._error_buffer[error["fingerprint"]] = error
                else:
                    entry["count"] += error["count"]
        except Exception:
            logger.exception("failed to record error %r", error.get("type"))

    def _read_rss(self):
        if sys.platform.startswith("linux"):
            try:
                with open("/proc/self/status") as status:
                    for line in status:
                        if line.startswith("VmRSS:"):
                            return int(line.split()[1]) * 1024  # value is in kB
            except (OSError, ValueError, IndexError) as exc:
                logger.debug("could not read VmRSS from /proc/self/status: %s", exc)
        if resource is not None:
            # Fallback: ru_maxrss is a lifetime high-water mark, not current RSS.
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform != "darwin":  # ru_maxrss is KB on Linux, bytes on macOS
                rss *= 1024
            return rss
        return None

    def _snapshot_record(self, snapshot, name, kind, unit, value):
        # Direct write into the just-drained snapshot, bypassing the entry cap.
        key = (name, _tags_key(self.tags))
        entry = {"name": name, "kind": kind, "unit": unit, "tags": dict(self.tags)}
        if kind == "counter":
            entry.update(count=1, sum=float(value))
            old = snapshot.get(key)
            if old is not None and old["kind"] == "counter":
                entry["count"] += old["count"]
                entry["sum"] += old["sum"]
        else:
            entry["value"] = float(value)
        snapshot[key] = entry

    def _record_runtime(self, snapshot):
        # Written straight into the drained snapshot: a full live buffer can
        # never starve these, and they don't count against the entry cap.
        try:
            rss = self._read_rss()
            if rss is not None:
                self._snapshot_record(snapshot, "process.memory.rss_bytes", "gauge", "bytes", rss)
            wall = time.monotonic()
            t = os.times()
            cpu = t.user + t.system
            last_cpu, last_wall = self._cpu_sample
            if wall > last_wall:
                self._snapshot_record(snapshot, "process.cpu.percent", "gauge", "%",
                                      100.0 * (cpu - last_cpu) / (wall - last_wall))
                self._cpu_sample = (cpu, wall)  # baseline advances only when recorded
            self._snapshot_record(snapshot, "process.threads", "gauge", None,
                                  threading.active_count())
            collections = sum(s.get("collections", 0) for s in gc.get_stats())
            self._snapshot_record(snapshot, "process.gc.collections", "counter", None,
                                  collections - self._gc_total)
            self._gc_total = collections
            self._snapshot_record(snapshot, "process.uptime_seconds", "gauge", "s",
                                  wall - self._started)
        except Exception:
            logger.exception("runtime metrics collection failed")

    def flush(self):
        """Send everything aggregated so far. Synchronous."""
        # One flush at a time: the background loop and public flush() would
        # otherwise interleave and race the cpu/gc baselines.
        with self._flush_lock:
            if time.monotonic() < self._retry_at:
                return
            with self._lock:
                snapshot = self._buffer
                self._buffer = {}
                tx_snapshot = self._tx_buffer
                self._tx_buffer = {}
                err_snapshot = self._error_buffer
                self._error_buffer = {}
                trace_snapshot = self._trace_samples
                self._trace_samples = []
                log_snapshot = self._log_buffer
                self._log_buffer = []
                logs_dropped, self._logs_dropped = self._logs_dropped, 0
                self._warned.clear()
            if logs_dropped:
                logger.warning("dropped %d log records since the last flush: buffer at its cap",
                               logs_dropped)
            if self.runtime_metrics:
                self._record_runtime(snapshot)
            self._record_lag_gauges(snapshot)
            buffers = (snapshot, tx_snapshot, err_snapshot, trace_snapshot)
            if any(buffers):
                payload = self._build_payload(*buffers)
                try:
                    self._send(payload)
                except _UnserializableError as exc:
                    logger.warning("dropping %d unserializable metric entries: %s",
                                   len(payload["metrics"]), exc)
                except _HttpStatusError as exc:
                    self._handle_http_error(buffers, payload, exc)
                except Exception as exc:
                    logger.warning("flush of %d metric entries to %s failed: %s",
                                   len(payload["metrics"]), self.ingest_url, exc)
                    self._merge_back(*buffers)
            if log_snapshot:
                self._flush_logs(log_snapshot)
            self._flush_profile()
            self._flush_security_events()

    def _flush_logs(self, entries):
        try:
            self._send_logs({"service": self.service, "logs": entries})
        except _UnserializableError as exc:
            logger.warning("dropping %d unserializable log records: %s", len(entries), exc)
        except _HttpStatusError as exc:
            if 400 <= exc.code < 500 and exc.code != 429:
                logger.warning("dropping %d log records rejected by the API: %s",
                               len(entries), exc)
            else:
                self._merge_back_logs(entries, exc)
        except Exception as exc:
            self._merge_back_logs(entries, exc)

    def _merge_back_logs(self, entries, exc):
        # Unsent records go back in front of whatever accumulated meanwhile;
        # the cap drops the oldest. Guarded: the failure path must not raise.
        logger.warning("flush of %d log records to %s failed: %s",
                       len(entries), self.logs_url, exc)
        try:
            with self._lock:
                combined = entries + self._log_buffer
                overflow = len(combined) - MAX_LOG_ENTRIES
                if overflow > 0:
                    self._logs_dropped += overflow
                    combined = combined[overflow:]
                self._log_buffer = combined
        except Exception:
            logger.exception("merge-back of unsent log records failed; data lost")

    def _handle_http_error(self, buffers, payload, exc):
        if exc.code == 429:
            delay = self.interval_seconds
            if exc.retry_after:
                try:
                    delay = max(int(exc.retry_after), 1)
                except ValueError:
                    logger.warning("unparseable Retry-After %r; retrying in %ds",
                                   exc.retry_after, delay)
            self._retry_at = time.monotonic() + delay
            logger.warning("rate limited (HTTP 429); pausing flushes for %ds", delay)
            self._merge_back(*buffers)
        elif 400 <= exc.code < 500:
            # the API rejected the payload; resending it would fail forever
            logger.warning("dropping %d metric entries rejected by the API: %s",
                           len(payload["metrics"]), exc)
        else:
            logger.warning("flush of %d metric entries to %s failed: %s",
                           len(payload["metrics"]), self.ingest_url, exc)
            self._merge_back(*buffers)

    def _build_payload(self, snapshot, tx_snapshot, err_snapshot, trace_snapshot):
        metrics = []
        for entry in snapshot.values():
            metric = {"name": entry["name"], "kind": entry["kind"]}
            if entry["unit"]:
                metric["unit"] = entry["unit"]
            if entry["tags"]:
                metric["tags"] = entry["tags"]
            for field in ("count", "sum", "min", "max", "value"):
                if field in entry:
                    metric[field] = entry[field]
            if entry.get("buckets"):
                # stringified indexes: the buckets object is JSON, additive,
                # and ignored by servers that predate histograms
                metric["buckets"] = {str(i): c for i, c in entry["buckets"].items()}
            metrics.append(metric)
        payload = {
            "service": self.service,
            "language": "python",
            "hostname": self.hostname,
            "runtime": {
                "language_version": platform.python_version(),
                "pid": os.getpid(),
                "wrapper_version": VERSION,
            },
            "interval_seconds": self.interval_seconds,
            "metrics": metrics,
        }
        if self.service_version:
            payload["service_version"] = self.service_version
        if self.commit_sha:
            payload["commit_sha"] = self.commit_sha
        if self._kubernetes:
            payload["kubernetes"] = dict(self._kubernetes)
        if tx_snapshot:
            transactions = []
            for group in tx_snapshot.values():
                entry = {"name": group["name"], "type": group["type"],
                         "count": group["count"], "sum": group["sum"],
                         "min": group["min"], "max": group["max"],
                         "success": group["success"], "failed": group["failed"]}
                if group.get("buckets"):
                    entry["buckets"] = {str(i): c for i, c in group["buckets"].items()}
                if group["spans"]:
                    rows = []
                    for (span_type, subtype), row in group["spans"].items():
                        span_row = {"type": span_type}
                        if subtype:
                            span_row["subtype"] = subtype
                        span_row["count"] = row["count"]
                        span_row["sum"] = row["sum"]
                        rows.append(span_row)
                    entry["spans"] = rows
                transactions.append(entry)
            payload["transactions"] = transactions
        if err_snapshot:
            payload["errors"] = list(err_snapshot.values())
        if trace_snapshot:
            payload["trace_samples"] = sorted(
                trace_snapshot, key=lambda s: s["duration_ms"], reverse=True
            )
        return payload

    def _merge_back(self, snapshot, tx_snapshot=None, err_snapshot=None,
                    trace_snapshot=None):
        # Unsent aggregates fold into whatever accumulated meanwhile; the live
        # buffer is newer, so gauges keep the live value and the snapshot loses
        # ties for space at the cap. Guarded: flush's failure path must not raise.
        dropped = 0
        try:
            with self._lock:
                for key, old in snapshot.items():
                    entry = self._buffer.get(key)
                    if entry is None:
                        if len(self._buffer) >= MAX_USER_ENTRIES:
                            dropped += 1
                            continue
                        self._buffer[key] = old
                    elif entry["kind"] != old["kind"]:
                        self._warn_throttled(("merge-kind", key),
                                             "metric %r changed kind from %s to %s mid-flush; "
                                             "dropping unsent %s data",
                                             old["name"], old["kind"], entry["kind"], old["kind"])
                    elif old["kind"] in ("counter", "timer"):
                        entry["count"] += old["count"]
                        entry["sum"] += old["sum"]
                        if old["kind"] == "timer":
                            entry["min"] = min(entry["min"], old["min"])
                            entry["max"] = max(entry["max"], old["max"])
                            _merge_buckets(entry["buckets"], old.get("buckets", {}))
                for key, old in (tx_snapshot or {}).items():
                    group = self._tx_buffer.get(key)
                    if group is None:
                        if len(self._tx_buffer) >= MAX_TX_GROUPS:
                            dropped += 1
                            continue
                        self._tx_buffer[key] = old
                        continue
                    group["count"] += old["count"]
                    group["sum"] += old["sum"]
                    group["min"] = min(group["min"], old["min"])
                    group["max"] = max(group["max"], old["max"])
                    group["success"] += old["success"]
                    group["failed"] += old["failed"]
                    _merge_buckets(group["buckets"], old.get("buckets", {}))
                    for span_key, row in old["spans"].items():
                        existing = group["spans"].get(span_key)
                        if existing is None:
                            if len(group["spans"]) >= MAX_TX_BREAKDOWN_ROWS:
                                continue
                            group["spans"][span_key] = row
                        else:
                            existing["count"] += row["count"]
                            existing["sum"] += row["sum"]
                for fingerprint, old in (err_snapshot or {}).items():
                    entry = self._error_buffer.get(fingerprint)
                    if entry is None:
                        if len(self._error_buffer) >= MAX_ERRORS:
                            dropped += 1
                            continue
                        self._error_buffer[fingerprint] = old
                    else:
                        # the live entry is newer; keep its message and stack
                        entry["count"] += old["count"]
                if trace_snapshot:
                    combined = self._trace_samples + trace_snapshot
                    combined.sort(key=lambda s: s["duration_ms"], reverse=True)
                    self._trace_samples = combined[:MAX_TRACE_SAMPLES]
        except Exception:
            logger.exception("merge-back of unsent entries failed; data lost")
        if dropped:
            logger.warning("dropped %d unsent entries: buffers at their caps", dropped)

    def _send(self, payload):
        self._post(self.ingest_url, payload)

    def _send_logs(self, payload):
        self._post(self.logs_url, payload)

    def _get(self, url):
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Collector {self.token}",
                "Accept": "application/json",
                "User-Agent": f"roottrace_apm-python/{VERSION}",
                "Connection": "close",
            },
            method="GET",
        )
        _self_calls.active = True
        try:
            with urllib.request.urlopen(request, timeout=10, context=self._ssl_context) as response:
                # Bounded: this is parsed into a config that controls a
                # sampling loop, and an unbounded read from the network is not
                # something to do on the strength of the URL being ours.
                return json.loads(response.read(256 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise _HttpStatusError(exc.code, detail, exc.headers.get("Retry-After")) from exc
        finally:
            _self_calls.active = False

    def _post(self, url, payload):
        # Serialization gets its own try: a ValueError from the request below
        # (e.g. a bad URL) must not masquerade as a poison payload.
        try:
            body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise _UnserializableError(exc) from exc
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Authorization": f"Collector {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"roottrace_apm-python/{VERSION}",
                "Connection": "close",
            },
            method="POST",
        )
        _self_calls.active = True
        try:
            with urllib.request.urlopen(request, timeout=10, context=self._ssl_context) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise _HttpStatusError(exc.code, detail, exc.headers.get("Retry-After")) from exc
        finally:
            _self_calls.active = False

    def shutdown(self):
        self._stop.set()
        if self._profiler is not None:
            self._profiler.stop()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_seconds)
        self.flush()
        if time.monotonic() < self._retry_at:
            # the final flush was a no-op behind the 429 deadline
            with self._lock:
                abandoned = len(self._buffer)
            if abandoned:
                logger.warning(
                    "shutting down while rate limited; abandoning %d unsent metric entries",
                    abandoned)


_instance = None
_init_lock = threading.Lock()
_warned_no_init = False


def init(service=None, token=None, api_url=None, interval_seconds=None,
         tags=None, runtime_metrics=True, service_version=None,
         http_instrumentation=True, db_instrumentation=True,
         security_sinks=True,
         deployment=None, namespace=None, commit_sha=None) -> Apm:
    """Configure the singleton and start the background flush thread.

    ``db_instrumentation`` auto-instruments whichever supported database
    clients are installed (pymongo/motor, Elasticsearch, redis, asyncpg,
    SQLAlchemy) so transactions get db spans without code changes. For
    MongoDB, call init() before constructing the client — pymongo only
    applies listeners to clients created afterwards."""
    global _instance
    with _init_lock:
        if _instance is not None:
            logger.warning("roottrace_apm.init() called again; returning the existing instance")
            return _instance
        service = service or env("ROOTTRACE_APM_SERVICE")
        token = token or env("ROOTTRACE_APM_TOKEN") or env("ROOTTRACE_COLLECTOR_TOKEN")
        api_url = api_url or env("ROOTTRACE_API_URL", DEFAULT_API_URL)
        if service_version is None:
            # Deploy pipelines set this without touching app code; versions
            # power the dashboard's deploy markers and regression checks.
            service_version = env("ROOTTRACE_APM_SERVICE_VERSION") or None
        if commit_sha is None:
            # Binds the version to a git commit for regression findings.
            # GITHUB_SHA is the fallback so GitHub Actions works untouched.
            commit_sha = env("ROOTTRACE_APM_COMMIT_SHA") or env("GITHUB_SHA") or None
        if interval_seconds is None:
            raw = env("ROOTTRACE_APM_INTERVAL_SECONDS") or "30"
            try:
                interval_seconds = int(float(raw))
            except (ValueError, OverflowError):  # OverflowError: int(float("inf"))
                logger.warning("invalid ROOTTRACE_APM_INTERVAL_SECONDS %r; using 30", raw)
                interval_seconds = 30
        if not service:
            raise ValueError(
                "RootTrace APM needs a service name: pass service= or set ROOTTRACE_APM_SERVICE"
            )
        if not token:
            raise ValueError(
                "RootTrace APM needs a collector token: pass token= or set "
                "ROOTTRACE_APM_TOKEN (or ROOTTRACE_COLLECTOR_TOKEN)"
            )
        if urllib.parse.urlsplit(api_url).scheme not in ("http", "https"):
            raise ValueError(
                f"RootTrace APM needs an http(s) api_url, got {api_url!r}: "
                "pass api_url= or set ROOTTRACE_API_URL"
            )
        try:
            interval_seconds = int(interval_seconds)
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"invalid interval_seconds {interval_seconds!r}") from exc
        clamped = min(max(interval_seconds, 5), 3600)
        if clamped != interval_seconds:
            logger.warning("interval_seconds %d outside the server's 5-3600 range; using %d",
                           interval_seconds, clamped)
        if service_version is not None:
            service_version = str(service_version)
            if len(service_version) > MAX_SERVICE_VERSION_LENGTH:
                logger.warning("service_version longer than %d chars; truncating",
                               MAX_SERVICE_VERSION_LENGTH)
                service_version = service_version[:MAX_SERVICE_VERSION_LENGTH]
        _instance = Apm(
            service=service,
            token=token,
            api_url=api_url,
            interval_seconds=clamped,
            tags=tags,
            runtime_metrics=runtime_metrics,
            service_version=service_version,
            deployment=deployment,
            namespace=namespace,
            commit_sha=(str(commit_sha)[:64] if commit_sha else None),
        )
        if http_instrumentation:
            _instrument_http_client()
            _instrument_httpx()
            _instrument_aiohttp()
        if db_instrumentation:
            _instrument_databases()
        if security_sinks:
            _instrument_security_sinks()
        _instance._start()
        atexit.register(shutdown)
        return _instance


def _record(name, kind, tags, unit, value):
    global _warned_no_init
    apm = _instance
    if apm is None:
        if not _warned_no_init:
            _warned_no_init = True
            logger.warning("metric recorded before roottrace_apm.init(); dropping")
        return
    apm._record(name, kind, tags, unit, value)


_module_warned = set()  # throttle for warnings raised while no instance exists


def _warn_throttled(key, msg, *args):
    apm = _instance
    if apm is not None:
        apm._warn_throttled(key, msg, *args)
    elif key not in _module_warned:
        _module_warned.add(key)
        logger.warning(msg, *args)


class Counter:
    def __init__(self, name, tags=None, unit=None):
        self.name = name
        self.tags = tags
        self.unit = unit

    def add(self, amount=1):
        _record(self.name, "counter", self.tags, self.unit, amount)


class Gauge:
    def __init__(self, name, tags=None, unit=None):
        self.name = name
        self.tags = tags
        self.unit = unit

    def set(self, value):
        _record(self.name, "gauge", self.tags, self.unit, value)


class Timer:
    def __init__(self, name, tags=None, unit="ms"):
        self.name = name
        self.tags = tags
        self.unit = unit

    def record(self, duration_ms):
        _record(self.name, "timer", self.tags, self.unit, duration_ms)

    def __enter__(self):
        # A per-context stack, so nested `with` blocks on one Timer work and
        # concurrent threads or asyncio tasks never see each other's starts.
        _stack_push(_timer_starts, (self, time.perf_counter()))
        return self

    def __exit__(self, exc_type, exc, tb):
        entry = _stack_pop(_timer_starts, self)
        if entry is not None:
            self.record((time.perf_counter() - entry[1]) * 1000.0)
        return False


def counter(name, tags=None, unit=None) -> Counter:
    return Counter(name, tags, unit)


def gauge(name, tags=None, unit=None) -> Gauge:
    return Gauge(name, tags, unit)


def timer(name, tags=None, unit="ms") -> Timer:
    return Timer(name, tags, unit)


def timed(name, tags=None, unit="ms"):
    """Decorator: record the wrapped call's duration as a timer metric."""
    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                _record(name, "timer", tags, unit, (time.perf_counter() - start) * 1000.0)
        return wrapper
    return decorate


class _Transaction:
    """One in-flight unit of work: timing, spans, and the trace id."""

    def __init__(self, name, type, trace_id):
        self.name = str(name)[:MAX_NAME_LENGTH] or "unnamed"
        self.type = str(type)[:MAX_TX_TYPE_LENGTH] or "request"
        self.trace_id = trace_id
        self.started_at = time.time()
        self.spans = []  # kept for the trace sample, capped
        self.spans_dropped = 0
        self.closed = False  # set once recorded; late spans then no-op
        self.failed = False  # forced by capture_exception(handled=False)
        self.http = None  # request context; rides the trace sample when set
        self.breakdown = {}  # (type, subtype) -> {"count", "sum"}
        self._start = time.perf_counter()
        self._token = None  # contextvar reset token, set by whoever activates us

    def _add_span(self, name, type, subtype, start_offset_ms, duration_ms):
        name = str(name)[:MAX_NAME_LENGTH] or "unnamed"
        type = str(type)[:MAX_TX_TYPE_LENGTH] or "custom"
        subtype = str(subtype)[:MAX_SUBTYPE_LENGTH] if subtype else None
        row = self.breakdown.get((type, subtype))
        if row is None:
            self.breakdown[(type, subtype)] = row = {"count": 0, "sum": 0.0}
        row["count"] += 1
        row["sum"] += duration_ms
        if len(self.spans) >= MAX_SAMPLE_SPANS:
            self.spans_dropped += 1
            return
        span = {"name": name, "type": type}
        if subtype:
            span["subtype"] = subtype
        span["start_offset_ms"] = start_offset_ms
        span["duration_ms"] = duration_ms
        self.spans.append(span)

    def set_http(self, method=None, path=None, status_code=None,
                 client_ip=None, remote_ip=None, user_agent=None):
        """Attach request details to this transaction. When it wins a
        trace-sample slot they ship as the sample's "http" object, so the
        dashboard can show where a slow or failing request came from.
        None leaves a field unset; values are clipped. Never raises."""
        try:
            http = self.http
            if http is None:
                http = self.http = {}
            for key, value, cap in (
                ("method", method, MAX_TX_TYPE_LENGTH),
                ("path", path, MAX_HTTP_PATH_LENGTH),
                ("client_ip", client_ip, MAX_HTTP_IP_LENGTH),
                ("remote_ip", remote_ip, MAX_HTTP_IP_LENGTH),
                ("user_agent", user_agent, MAX_HTTP_USER_AGENT_LENGTH),
            ):
                if value is not None:
                    http[key] = str(value)[:cap]
            if status_code is not None:
                try:
                    code = int(status_code)
                except (TypeError, ValueError):
                    code = None
                # The server rejects codes outside 0-999 — and a rejected
                # payload takes the whole flush down with it.
                if code is not None and 0 <= code <= 999:
                    http["status_code"] = code
                else:
                    _warn_throttled(("http-status-code", self.name),
                                    "ignoring invalid status_code %r on transaction %r",
                                    status_code, self.name)
        except Exception:
            logger.exception("failed to set http context on transaction %r", self.name)


def _finish_transaction(tx, outcome):
    global _warned_no_init
    tx.closed = True  # late spans (e.g. WSGI streaming) must not attach anymore
    if tx.failed:
        outcome = "failed"
    apm = _instance
    if apm is None:
        if not _warned_no_init:
            _warned_no_init = True
            logger.warning("transaction finished before roottrace_apm.init(); dropping")
        return
    apm._record_transaction(tx, (time.perf_counter() - tx._start) * 1000.0, outcome)


class _TransactionContext:
    """Context manager and decorator wrapping work in a transaction."""

    def __init__(self, name, type, traceparent=None):
        self.name = name
        self.type = type
        self.traceparent = traceparent
        self._tx = None  # the transaction this context opened, nothing else

    def __enter__(self):
        # Guarded: starting a transaction must never raise into the app.
        try:
            trace_id = _parse_traceparent(self.traceparent) or os.urandom(16).hex()
            tx = _Transaction(self.name, self.type, trace_id)
            tx._token = _active_transaction.set(tx)
            self._tx = tx
            return tx
        except Exception:
            logger.exception("failed to start transaction %r", self.name)
            return None

    def __exit__(self, exc_type, exc, tb):
        try:
            # Only close what __enter__ opened: if it failed inside an outer
            # transaction, the outer one must not be recorded early.
            tx, self._tx = self._tx, None
            if tx is None:
                return False
            outcome = "success"
            if exc is not None:
                outcome = "failed"
                if isinstance(exc, Exception):
                    _capture_error(exc, tx.name)
            try:
                _active_transaction.reset(tx._token)
            except ValueError:  # exiting in a different context than we entered
                _active_transaction.set(None)
            _finish_transaction(tx, outcome)
        except Exception:
            logger.exception("failed to finish transaction")
        return False  # an exception from the body re-raises unchanged

    def __call__(self, fn):
        # A fresh context per call: concurrent calls must not share _tx. For
        # coroutine functions the transaction must span the await, not just
        # the (instant) coroutine creation.
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                with _TransactionContext(self.name, self.type, self.traceparent):
                    return await fn(*args, **kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with _TransactionContext(self.name, self.type, self.traceparent):
                return fn(*args, **kwargs)
        return wrapper


def transaction(name, type="request", traceparent=None) -> _TransactionContext:
    """Track a unit of work. Use as a context manager or a decorator.

    Pass a W3C ``traceparent`` header value to adopt an incoming trace id.
    """
    return _TransactionContext(name, type, traceparent)


class Span:
    """Times an operation inside the active transaction; no-op without one."""

    def __init__(self, name, type="custom", subtype=None):
        self.name = name
        self.type = type
        self.subtype = subtype

    def __enter__(self):
        try:
            # A per-context stack, so nested `with` blocks on one Span work
            # and interleaved asyncio tasks never pop each other's starts.
            _stack_push(_span_starts, (self, _current_transaction(), time.perf_counter()))
        except Exception:
            logger.exception("failed to start span %r", self.name)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            entry = _stack_pop(_span_starts, self)
            if entry is not None:
                _, tx, start = entry
                # No active transaction, or it closed while the span was
                # open (WSGI streaming): the span is a no-op.
                if tx is not None and not tx.closed:
                    tx._add_span(self.name, self.type, self.subtype,
                                 (start - tx._start) * 1000.0,
                                 (time.perf_counter() - start) * 1000.0)
        except Exception:
            logger.exception("failed to finish span %r", self.name)
        return False


def span(name, type="custom", subtype=None) -> Span:
    return Span(name, type, subtype)


# Files under these directories are stdlib or third-party, not the app.
_NON_APP_DIRS = (os.path.dirname(os.__file__), os.path.dirname(os.path.abspath(__file__)))


def _is_app_file(path):
    if not path or path.startswith("<"):
        return False
    if "site-packages" in path or "dist-packages" in path:
        return False
    return not path.startswith(_NON_APP_DIRS)


def _build_error(exc):
    frames = []
    tb = exc.__traceback__
    while tb is not None:
        code = tb.tb_frame.f_code
        frames.append({  # clipped to the server schema; fingerprints use these values
            "function": code.co_name[:MAX_FRAME_FUNCTION_LENGTH],
            "file": code.co_filename[:MAX_FRAME_FILE_LENGTH],
            "line": tb.tb_lineno,
            "module": tb.tb_frame.f_globals.get("__name__", ""),
        })
        tb = tb.tb_next
    culprit_frame = None
    for frame in reversed(frames):  # deepest app frame; else deepest frame
        if _is_app_file(frame["file"]):
            culprit_frame = frame
            break
    if culprit_frame is None and frames:
        culprit_frame = frames[-1]
    if culprit_frame is None:
        culprit = "<unknown>"
    elif culprit_frame["module"]:
        culprit = f"{culprit_frame['module']}.{culprit_frame['function']}"
    else:
        culprit = culprit_frame["function"]
    culprit = culprit[:MAX_CULPRIT_LENGTH]
    # keep the innermost frames when the stack is deep; outermost-first order
    frames = frames[-MAX_STACK_FRAMES:]
    stack = [{"function": f["function"], "file": f["file"], "line": f["line"]}
             for f in frames]
    type_name = type(exc).__name__[:MAX_ERROR_TYPE_LENGTH]
    digest = hashlib.sha256()
    digest.update(type_name.encode("utf-8", errors="replace"))
    digest.update(culprit.encode("utf-8", errors="replace"))
    for frame in stack[-5:]:  # the frames closest to the raise identify it
        digest.update(f"{frame['file']}:{frame['function']}".encode("utf-8", errors="replace"))
    return {
        "fingerprint": digest.hexdigest()[:16],
        "type": type_name,
        "message": str(exc)[:MAX_MESSAGE_LENGTH],
        "culprit": culprit,
        "count": 1,
        "stack": stack,
    }


def _capture_error(exc, transaction_name):
    # Guarded end to end: error capture must never raise into the app.
    global _warned_no_init
    try:
        apm = _instance
        if apm is None:
            if not _warned_no_init:
                _warned_no_init = True
                logger.warning("exception captured before roottrace_apm.init(); dropping")
            return
        if not isinstance(exc, BaseException):
            _warn_throttled("capture-not-exception",
                            "capture_exception() got %r, not an exception; ignoring", exc)
            return
        error = _build_error(exc)
        if transaction_name:
            error["transaction_name"] = transaction_name
        apm._record_error(error)
    except Exception:
        logger.exception("failed to capture exception")


def capture_exception(exc, handled=True):
    """Record an exception in the errors buffer. Never raises.

    ``handled=False`` also marks the active transaction failed.
    """
    tx = _current_transaction()
    if not handled and tx is not None:
        tx.failed = True
    _capture_error(exc, tx.name if tx is not None else None)


def flush():
    if _instance is not None:
        _instance.flush()


def watch_event_loop():
    """Start the event-loop lag monitor on the current running loop."""
    if _instance is not None:
        _instance.watch_event_loop()


def shutdown():
    global _instance
    with _init_lock:
        apm = _instance
        if apm is None:
            return
        try:
            apm.shutdown()
        finally:
            _instance = None  # a later init() builds a fresh instance


_http_client_patched = False


def _instrument_http_client():
    """Patch http.client so outbound calls report metrics, spans, and
    propagate traceparent. Idempotent; every path falls back to the
    original methods on any internal error.

    request() alone is not enough: urllib3 2.x overrides it without calling
    the stdlib one, but still funnels through putrequest/endheaders (via
    super()) and getresponse, so those carry the timing and header injection
    for that path. putrequest only starts timing when request() hasn't
    already (request() calls putrequest internally)."""
    global _http_client_patched
    if _http_client_patched:
        return
    original_request = http.client.HTTPConnection.request
    original_putrequest = http.client.HTTPConnection.putrequest
    original_endheaders = http.client.HTTPConnection.endheaders
    original_getresponse = http.client.HTTPConnection.getresponse

    def pop_pending(conn):
        # Cleared unconditionally, no _instance check: pending state must not
        # leak across shutdown/re-init on a keep-alive connection.
        pending = getattr(conn, "_roottrace_apm", None)
        if pending is not None:
            conn._roottrace_apm = None
        return pending

    def finish(conn, pending, status):
        start, method = pending
        duration = (time.perf_counter() - start) * 1000.0
        destination = f"{conn.host}:{conn.port}"
        tags = {"destination": destination, "status": status}
        _record("http.client.duration", "timer", tags, "ms", duration)
        _record("http.client.requests", "counter", tags, None, 1)
        tx = _current_transaction()
        if tx is not None and not _span_suppressed.get():
            tx._add_span(f"{method} {destination}", "http", destination,
                         (start - tx._start) * 1000.0, duration)

    def fail(conn):
        # Guarded: recording the failure must never mask the original exception.
        try:
            pending = pop_pending(conn)
            if pending is not None and _instance is not None:
                finish(conn, pending, "error")
        except Exception as exc:
            _warn_throttled("http-failure-instrumentation",
                            "outbound HTTP failure instrumentation failed (%r)", exc)

    def request(conn, method, url, body=None, headers=None, **kwargs):
        try:
            if _instance is not None and not getattr(_self_calls, "active", False):
                conn._roottrace_apm = (time.perf_counter(), str(method))
                tx = _current_transaction()
                if tx is not None:
                    headers = dict(headers) if headers else {}
                    if not any(str(k).lower() == "traceparent" for k in headers):
                        headers["traceparent"] = (
                            f"00-{tx.trace_id}-{os.urandom(8).hex()}-01"
                        )
        except Exception as exc:
            _warn_throttled("http-request-instrumentation",
                            "outbound HTTP instrumentation failed (%r); "
                            "sending the request uninstrumented", exc)
        try:
            return original_request(conn, method, url, body, headers or {}, **kwargs)
        except Exception:
            fail(conn)
            raise

    def putrequest(conn, method, url, *args, **kwargs):
        try:
            if (_instance is not None and not getattr(_self_calls, "active", False)
                    and getattr(conn, "_roottrace_apm", None) is None):
                conn._roottrace_apm = (time.perf_counter(), str(method))
        except Exception as exc:
            _warn_throttled("http-putrequest-instrumentation",
                            "outbound HTTP instrumentation failed (%r); "
                            "sending the request uninstrumented", exc)
        try:
            return original_putrequest(conn, method, url, *args, **kwargs)
        except Exception:
            fail(conn)
            raise

    def endheaders(conn, *args, **kwargs):
        try:
            if getattr(conn, "_roottrace_apm", None) is not None:
                tx = _current_transaction()
                # _buffer holds the headers already put; don't inject a second
                # traceparent when the caller (or request() above) set one.
                if tx is not None and not any(
                    line.lower().startswith(b"traceparent:")
                    for line in getattr(conn, "_buffer", ())
                ):
                    conn.putheader("traceparent",
                                   f"00-{tx.trace_id}-{os.urandom(8).hex()}-01")
        except Exception as exc:
            _warn_throttled("http-endheaders-instrumentation",
                            "outbound HTTP instrumentation failed (%r); "
                            "sending the request uninstrumented", exc)
        try:
            return original_endheaders(conn, *args, **kwargs)
        except Exception:
            fail(conn)  # connect errors (refused, DNS) surface here
            raise

    def getresponse(conn, *args, **kwargs):
        try:
            response = original_getresponse(conn, *args, **kwargs)
        except Exception:
            fail(conn)  # timeouts waiting on the response surface here
            raise
        pending = pop_pending(conn)
        try:
            if pending is not None and _instance is not None:
                status = response.status
                bucket = (f"{status // 100}xx"
                          if isinstance(status, int) and 100 <= status <= 599
                          else "unknown")
                finish(conn, pending, bucket)
        except Exception as exc:
            _warn_throttled("http-response-instrumentation",
                            "outbound HTTP instrumentation failed (%r); "
                            "returning the response uninstrumented", exc)
        return response

    http.client.HTTPConnection.request = request
    http.client.HTTPConnection.putrequest = putrequest
    http.client.HTTPConnection.endheaders = endheaders
    http.client.HTTPConnection.getresponse = getresponse
    _http_client_patched = True


_httpx_patched = False
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _instrument_httpx():
    """Patch httpx.Client.send / httpx.AsyncClient.send with the same
    reporting as the http.client instrumentation. httpx rides httpcore,
    not http.client, so it needs its own hook. send() is the funnel every
    request passes through in both clients; with follow_redirects a whole
    redirect chain is one call, recorded against the original destination
    with the final status. Idempotent; missing httpx is not an error."""
    global _httpx_patched
    if _httpx_patched:
        return
    try:
        import httpx
    except ImportError:
        return

    original_send = httpx.Client.send
    original_async_send = httpx.AsyncClient.send

    def before(request):
        # Returns the start time, or None when instrumentation is off.
        if _instance is None or getattr(_self_calls, "active", False):
            return None
        try:
            tx = _current_transaction()
            if tx is not None and "traceparent" not in request.headers:
                request.headers["traceparent"] = (
                    f"00-{tx.trace_id}-{os.urandom(8).hex()}-01"
                )
        except Exception as exc:
            _warn_throttled("httpx-request-instrumentation",
                            "httpx instrumentation failed (%r); "
                            "sending the request uninstrumented", exc)
        return time.perf_counter()

    def finish(request, start, status):
        # Guarded: recording must never mask the response or the exception.
        try:
            if start is None or _instance is None:
                return
            duration = (time.perf_counter() - start) * 1000.0
            host = request.url.host or "unknown"
            port = request.url.port or _DEFAULT_PORTS.get(request.url.scheme)
            destination = f"{host}:{port}" if port else host
            tags = {"destination": destination, "status": status}
            _record("http.client.duration", "timer", tags, "ms", duration)
            _record("http.client.requests", "counter", tags, None, 1)
            tx = _current_transaction()
            if tx is not None and not _span_suppressed.get():
                tx._add_span(f"{request.method} {destination}", "http", destination,
                             (start - tx._start) * 1000.0, duration)
        except Exception as exc:
            _warn_throttled("httpx-response-instrumentation",
                            "httpx instrumentation failed (%r); "
                            "the call itself succeeded or raised as usual", exc)

    def bucket(response):
        status = response.status_code
        return (f"{status // 100}xx"
                if isinstance(status, int) and 100 <= status <= 599
                else "unknown")

    # BaseException, not Exception: asyncio cancellation (client
    # disconnect, wait_for timeout) must still record the call as an
    # error before re-raising, or cancelled requests vanish from APM.
    @functools.wraps(original_send)
    def send(client, request, **kwargs):
        start = before(request)
        try:
            response = original_send(client, request, **kwargs)
        except BaseException:
            finish(request, start, "error")
            raise
        finish(request, start, bucket(response))
        return response

    @functools.wraps(original_async_send)
    async def async_send(client, request, **kwargs):
        start = before(request)
        try:
            response = await original_async_send(client, request, **kwargs)
        except BaseException:
            finish(request, start, "error")
            raise
        finish(request, start, bucket(response))
        return response

    httpx.Client.send = send
    httpx.AsyncClient.send = async_send
    _httpx_patched = True


def _add_db_span(name, subtype, duration_ms, start_perf=None):
    """Attach a db span to the active transaction; no-op without one.

    When only a duration is known (pymongo listener events), the start
    offset is back-computed from now. Guarded: never raises."""
    try:
        tx = _current_transaction()
        if tx is None:
            return
        end = time.perf_counter()
        start = start_perf if start_perf is not None else end - duration_ms / 1000.0
        tx._add_span(name, "db", subtype, (start - tx._start) * 1000.0, duration_ms)
    except Exception as exc:
        _warn_throttled("db-span", "db span recording failed (%r)", exc)


_SQL_TABLE_RE = re.compile(r"\b(?:from|into|update|join)\s+([A-Za-z0-9_.\"]+)",
                           re.IGNORECASE)


def _sql_span_name(statement):
    # "SELECT users" / "INSERT orders": the operation plus a best-effort
    # table name, never the statement itself (parameters may be inlined).
    text = str(statement).strip()
    if not text:
        return "SQL"
    op = text.split(None, 1)[0].upper()[:20]
    match = _SQL_TABLE_RE.search(text)
    return f"{op} {match.group(1)}" if match else op


_aiohttp_patched = False


def _instrument_aiohttp():
    """Patch aiohttp.ClientSession._request with the same reporting as the
    other HTTP hooks. _request is the funnel under get/post/etc. for both
    plain sessions and clients built on aiohttp (async Elasticsearch, the
    embedding service). Idempotent; missing aiohttp is not an error."""
    global _aiohttp_patched
    if _aiohttp_patched:
        return
    try:
        import aiohttp
    except ImportError:
        return

    original_request = aiohttp.ClientSession._request

    def inject_traceparent(kwargs):
        try:
            if _instance is None:
                return None
            tx = _current_transaction()
            if tx is None:
                return time.perf_counter()
            headers = kwargs.get("headers")
            if headers is None:
                kwargs["headers"] = {
                    "traceparent": f"00-{tx.trace_id}-{os.urandom(8).hex()}-01"
                }
            elif hasattr(headers, "keys") and not any(
                str(k).lower() == "traceparent" for k in headers.keys()
            ):
                headers = dict(headers)
                headers["traceparent"] = f"00-{tx.trace_id}-{os.urandom(8).hex()}-01"
                kwargs["headers"] = headers
            # a list of pairs is passed through untouched: appending a
            # duplicate traceparent would be worse than sending none
        except Exception as exc:
            _warn_throttled("aiohttp-request-instrumentation",
                            "aiohttp instrumentation failed (%r); "
                            "sending the request uninstrumented", exc)
        return time.perf_counter()

    def finish(method, url, response, start, status):
        # Guarded: recording must never mask the response or the exception.
        try:
            if start is None or _instance is None:
                return
            duration = (time.perf_counter() - start) * 1000.0
            target = response.url if response is not None else None
            if target is None:
                parts = urllib.parse.urlsplit(str(url))
                host, port, scheme = parts.hostname, parts.port, parts.scheme
            else:
                host, port, scheme = target.host, target.port, target.scheme
            port = port or _DEFAULT_PORTS.get(scheme)
            destination = (f"{host}:{port}" if port else host) or "unknown"
            tags = {"destination": destination, "status": status}
            _record("http.client.duration", "timer", tags, "ms", duration)
            _record("http.client.requests", "counter", tags, None, 1)
            tx = _current_transaction()
            if tx is not None and not _span_suppressed.get():
                tx._add_span(f"{str(method).upper()} {destination}", "http",
                             destination, (start - tx._start) * 1000.0, duration)
        except Exception as exc:
            _warn_throttled("aiohttp-response-instrumentation",
                            "aiohttp instrumentation failed (%r); "
                            "the call itself succeeded or raised as usual", exc)

    @functools.wraps(original_request)
    async def request(session, method, str_or_url, **kwargs):
        start = inject_traceparent(kwargs)
        try:
            response = await original_request(session, method, str_or_url, **kwargs)
        except BaseException:  # cancellation must still record, then re-raise
            finish(method, str_or_url, None, start, "error")
            raise
        status = response.status
        bucket = (f"{status // 100}xx"
                  if isinstance(status, int) and 100 <= status <= 599
                  else "unknown")
        finish(method, str_or_url, response, start, bucket)
        return response

    aiohttp.ClientSession._request = request
    _aiohttp_patched = True


_pymongo_patched = False

# Handshake, heartbeat, and auth traffic is driver bookkeeping, not
# application work; it would drown real commands in the waterfall.
_MONGO_SKIP_COMMANDS = frozenset((
    "hello", "ismaster", "isMaster", "ping", "endSessions", "abortTransaction",
    "saslStart", "saslContinue", "authenticate", "buildInfo", "getnonce",
))


def _make_mongo_listener():
    """Build the pymongo CommandListener (module-level for tests)."""
    from pymongo import monitoring

    class Listener(monitoring.CommandListener):
        def __init__(self):
            # request_id -> collection, so succeeded/failed can name the
            # span. Bounded: commands can fail without an event, so the
            # map is cleared at a cap rather than trusted to drain.
            self._pending = {}

        def started(self, event):
            try:
                if event.command_name in _MONGO_SKIP_COMMANDS:
                    return
                if len(self._pending) > 2048:
                    self._pending.clear()
                target = event.command.get(event.command_name) if event.command else None
                if isinstance(target, str):
                    self._pending[event.request_id] = target
            except Exception as exc:
                _warn_throttled("pymongo-instrumentation",
                                "mongodb span recording failed (%r)", exc)

        def succeeded(self, event):
            self._finish(event)

        def failed(self, event):
            self._finish(event)

        def _finish(self, event):
            try:
                collection = self._pending.pop(event.request_id, None)
                if event.command_name in _MONGO_SKIP_COMMANDS or _instance is None:
                    return
                database = getattr(event, "database_name", None)
                scope = ".".join(p for p in (database, collection) if p)
                name = f"{event.command_name} {scope}" if scope else event.command_name
                _add_db_span(name, "mongodb", event.duration_micros / 1000.0)
            except Exception as exc:
                _warn_throttled("pymongo-instrumentation",
                                "mongodb span recording failed (%r)", exc)

    return Listener()


def _patch_motor_context():
    """Make motor's executor calls carry the caller's context, so pymongo
    listener callbacks (which fire on those worker threads) can see the
    active transaction. Without this, motor commands record no spans."""
    try:
        from motor import frameworks
        module = frameworks.asyncio
    except Exception:
        return  # motor absent or reorganized; plain pymongo still works
    if getattr(module, "_roottrace_apm_context", False):
        return
    original = module.run_on_executor

    @functools.wraps(original)
    def run_on_executor(loop, fn, *args, **kwargs):
        ctx = contextvars.copy_context()
        return original(loop, functools.partial(ctx.run, fn), *args, **kwargs)

    module.run_on_executor = run_on_executor
    module._roottrace_apm_context = True


def _instrument_pymongo():
    """Register a global pymongo command listener. Global listeners only
    apply to clients created afterwards, so init() must run before the
    MongoClient / motor client is constructed."""
    global _pymongo_patched
    if _pymongo_patched:
        return
    try:
        from pymongo import monitoring
    except ImportError:
        return
    _patch_motor_context()
    monitoring.register(_make_mongo_listener())
    _pymongo_patched = True


_elasticsearch_patched = False


def _instrument_elasticsearch():
    """Wrap Elasticsearch.perform_request (sync and async) in a db span.
    The transport's own HTTP call is suppressed from the waterfall so one
    query doesn't appear twice; http.client.* metrics still record."""
    global _elasticsearch_patched
    if _elasticsearch_patched:
        return
    try:
        import elasticsearch
    except ImportError:
        return

    def span_name(args, kwargs):
        method = str(args[0]) if args else kwargs.get("method", "REQUEST")
        path = str(args[1]) if len(args) > 1 else str(kwargs.get("path", "/"))
        return f"{method} {_normalize_path(path)}"

    def wrap_sync(original):
        @functools.wraps(original)
        def perform_request(client, *args, **kwargs):
            start = time.perf_counter()
            token = _span_suppressed.set(True)
            try:
                return original(client, *args, **kwargs)
            finally:
                _span_suppressed.reset(token)
                _add_db_span(span_name(args, kwargs), "elasticsearch",
                             (time.perf_counter() - start) * 1000.0, start)
        return perform_request

    def wrap_async(original):
        @functools.wraps(original)
        async def perform_request(client, *args, **kwargs):
            start = time.perf_counter()
            token = _span_suppressed.set(True)
            try:
                return await original(client, *args, **kwargs)
            finally:
                _span_suppressed.reset(token)
                _add_db_span(span_name(args, kwargs), "elasticsearch",
                             (time.perf_counter() - start) * 1000.0, start)
        return perform_request

    patched = False
    sync_client = getattr(elasticsearch, "Elasticsearch", None)
    if sync_client is not None and hasattr(sync_client, "perform_request"):
        sync_client.perform_request = wrap_sync(sync_client.perform_request)
        patched = True
    async_client = getattr(elasticsearch, "AsyncElasticsearch", None)
    if async_client is not None and hasattr(async_client, "perform_request"):
        async_client.perform_request = wrap_async(async_client.perform_request)
        patched = True
    _elasticsearch_patched = patched


_redis_patched = False


def _instrument_redis():
    """Wrap redis-py execute_command (sync and asyncio) in a db span named
    by the command ("GET", "HSET", ...), never by key."""
    global _redis_patched
    if _redis_patched:
        return
    try:
        import redis
    except ImportError:
        return

    def wrap_sync(original):
        @functools.wraps(original)
        def execute_command(client, *args, **options):
            start = time.perf_counter()
            try:
                return original(client, *args, **options)
            finally:
                _add_db_span(str(args[0]) if args else "COMMAND", "redis",
                             (time.perf_counter() - start) * 1000.0, start)
        return execute_command

    def wrap_async(original):
        @functools.wraps(original)
        async def execute_command(client, *args, **options):
            start = time.perf_counter()
            try:
                return await original(client, *args, **options)
            finally:
                _add_db_span(str(args[0]) if args else "COMMAND", "redis",
                             (time.perf_counter() - start) * 1000.0, start)
        return execute_command

    redis.Redis.execute_command = wrap_sync(redis.Redis.execute_command)
    try:
        import redis.asyncio
        redis.asyncio.Redis.execute_command = wrap_async(
            redis.asyncio.Redis.execute_command)
    except (ImportError, AttributeError):
        pass  # asyncio flavor absent on old redis-py; sync still covered
    _redis_patched = True


_asyncpg_patched = False


def _instrument_asyncpg():
    """Wrap asyncpg Connection query methods in postgresql db spans."""
    global _asyncpg_patched
    if _asyncpg_patched:
        return
    try:
        import asyncpg
    except ImportError:
        return

    def wrap(original):
        @functools.wraps(original)
        async def method(conn, query, *args, **kwargs):
            start = time.perf_counter()
            try:
                return await original(conn, query, *args, **kwargs)
            finally:
                _add_db_span(_sql_span_name(query), "postgresql",
                             (time.perf_counter() - start) * 1000.0, start)
        return method

    connection = asyncpg.connection.Connection
    for name in ("execute", "executemany", "fetch", "fetchrow", "fetchval"):
        if hasattr(connection, name):
            setattr(connection, name, wrap(getattr(connection, name)))
    _asyncpg_patched = True


_sqlalchemy_patched = False


def _instrument_sqlalchemy():
    """Listen for cursor execution on every SQLAlchemy engine (present and
    future: the listener attaches to the Engine class). Covers whatever
    dialect the app uses — postgresql, mysql, sqlite — as the subtype."""
    global _sqlalchemy_patched
    if _sqlalchemy_patched:
        return
    try:
        from sqlalchemy import event
        from sqlalchemy.engine import Engine
    except ImportError:
        return

    def before(conn, cursor, statement, parameters, context, executemany):
        try:
            conn.info.setdefault("_roottrace_apm_starts", []).append(time.perf_counter())
        except Exception:
            pass  # after() tolerates a missing start

    def after(conn, cursor, statement, parameters, context, executemany):
        try:
            starts = conn.info.get("_roottrace_apm_starts")
            if not starts:
                return
            start = starts.pop()
            subtype = getattr(getattr(conn, "dialect", None), "name", None) or "sql"
            _add_db_span(_sql_span_name(statement), subtype,
                         (time.perf_counter() - start) * 1000.0, start)
        except Exception as exc:
            _warn_throttled("sqlalchemy-instrumentation",
                            "sql span recording failed (%r)", exc)

    event.listen(Engine, "before_cursor_execute", before)
    event.listen(Engine, "after_cursor_execute", after)
    _sqlalchemy_patched = True


def _instrument_databases():
    # Each hook no-ops when its library is missing and never raises.
    for hook in (_instrument_pymongo, _instrument_elasticsearch,
                 _instrument_redis, _instrument_asyncpg, _instrument_sqlalchemy):
        try:
            hook()
        except Exception as exc:
            _warn_throttled(("db-instrumentation", hook.__name__),
                            "%s failed (%r); that client reports no spans",
                            hook.__name__, exc)


# Numeric, UUID-shaped, or long-hex (>=16 chars: Mongo ObjectIds, hashes)
# path segments become ":id" in transaction names.
_ID_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{16,}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


def _normalize_path(path):
    if not path:
        return "/"
    return "/".join(
        ":id" if _ID_SEGMENT_RE.match(segment) else segment
        for segment in path.split("/")
    ) or "/"


class WsgiMiddleware:
    """Wraps each request in a transaction and records the http.request.duration
    timer and http.requests counter, tagged by method and status class."""

    def __init__(self, app, name="http.request.duration", name_callback=None):
        self.app = app
        self.name = name
        self.name_callback = name_callback

    def _start_transaction(self, environ):
        # Guarded: the middleware must serve the request even if APM breaks.
        try:
            name = None
            if self.name_callback is not None:
                try:
                    name = self.name_callback(environ)
                except Exception:
                    _warn_throttled("wsgi-name-callback",
                                    "name_callback failed; using the default transaction name")
            if name is None:
                name = (f"{environ.get('REQUEST_METHOD', 'GET')} "
                        f"{_normalize_path(environ.get('PATH_INFO', ''))}")
            trace_id = (_parse_traceparent(environ.get("HTTP_TRACEPARENT"))
                        or os.urandom(16).hex())
            tx = _Transaction(name, "request", trace_id)
            remote = environ.get("REMOTE_ADDR") or None
            # client_ip is the first X-Forwarded-For hop — the caller's
            # claim of the origin, spoofable by whoever sent the request.
            # remote_ip is always the socket peer, so the one address the
            # kernel vouches for survives whatever the header says.
            client_ip = None
            forwarded = environ.get("HTTP_X_FORWARDED_FOR")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip() or None
            path = environ.get("PATH_INFO", "")
            query = environ.get("QUERY_STRING")
            tx.set_http(
                method=environ.get("REQUEST_METHOD", "GET"),
                path=f"{path}?{query}" if query else path,
                client_ip=client_ip or remote,
                remote_ip=remote,
                user_agent=environ.get("HTTP_USER_AGENT") or None,
            )
            tx._token = _active_transaction.set(tx)
            return tx
        except Exception:
            logger.exception("failed to start request transaction")
            return None

    def _finish_request(self, tx, outcome, exc):
        if tx is None:
            return
        try:
            if exc is not None:
                _capture_error(exc, tx.name)
            try:
                _active_transaction.reset(tx._token)
            except ValueError:  # streaming finished in a different context
                _active_transaction.set(None)
            _finish_transaction(tx, outcome)
        except Exception:
            logger.exception("failed to finish request transaction")

    def __call__(self, environ, start_response):
        tx = self._start_transaction(environ)
        start = time.perf_counter()
        captured = {}

        def capture(status, headers, exc_info=None):
            captured["status"] = status
            return start_response(status, headers, exc_info)

        try:
            result = self.app(environ, capture)
        except Exception as exc:
            self._finish_request(tx, "failed", exc)
            raise

        def stream(result):
            error = None
            try:
                yield from result
            except Exception as exc:
                error = exc
                raise
            finally:
                if hasattr(result, "close"):
                    result.close()
                status = captured.get("status", "")
                bucket = f"{status[:1]}xx" if status[:1].isdigit() else "unknown"
                # isdecimal, not isdigit: isdigit admits characters like
                # superscripts that int() rejects, and this must not raise.
                if tx is not None and status[:3].isdecimal():
                    tx.set_http(status_code=int(status[:3]))
                tags = {"method": environ.get("REQUEST_METHOD", "GET"), "status": bucket}
                _record(self.name, "timer", tags, "ms",
                        (time.perf_counter() - start) * 1000.0)
                _record("http.requests", "counter", tags, None, 1)
                outcome = "failed" if (error is not None or bucket == "5xx") else "success"
                self._finish_request(tx, outcome, error)

        return stream(result)


class AsgiMiddleware:
    """ASGI 3 middleware (FastAPI, Starlette, ...): wraps each http request
    in a transaction and records the http.request.duration timer and
    http.requests counter, tagged by method and status class. Non-http
    scopes (lifespan, websocket) pass straight through."""

    def __init__(self, app, name="http.request.duration"):
        self.app = app
        self.name = name

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        tx = self._start_transaction(scope)
        start = time.perf_counter()
        captured = {}

        async def wrapped_send(message):
            try:
                if message.get("type") == "http.response.start":
                    captured["status"] = message.get("status")
            except Exception:
                logger.exception("failed to capture response status")
            await send(message)

        error = None
        try:
            await self.app(scope, receive, wrapped_send)
        except Exception as exc:
            error = exc
            raise  # unchanged; instrumentation happens in finally
        finally:
            self._finish_request(scope, tx, captured.get("status"), start, error)

    def _start_transaction(self, scope):
        # Guarded: the middleware must serve the request even if APM breaks.
        try:
            apm = _instance
            if apm is not None:
                apm.watch_event_loop()  # idempotent; we are on the loop here
            wanted = {"traceparent": None, "x-forwarded-for": None, "user-agent": None}
            for key, value in scope.get("headers") or ():
                name = bytes(key).decode("latin-1").lower()
                if name in wanted and wanted[name] is None:  # first occurrence wins
                    wanted[name] = bytes(value).decode("latin-1")
            method = str(scope.get("method") or "GET")
            path = scope.get("path") or "/"
            # Named from the raw path for now; _finish_request switches to the
            # route template once the framework has resolved it.
            trace_id = _parse_traceparent(wanted["traceparent"]) or os.urandom(16).hex()
            tx = _Transaction(f"{method} {path}", "request", trace_id)
            client = scope.get("client")
            remote = client[0] if client else None
            client_ip = None
            if wanted["x-forwarded-for"]:
                client_ip = wanted["x-forwarded-for"].split(",")[0].strip() or None
            query = scope.get("query_string") or b""
            if isinstance(query, (bytes, bytearray)):
                query = bytes(query).decode("latin-1")
            tx.set_http(
                method=method,
                path=f"{path}?{query}" if query else path,
                client_ip=client_ip or remote,
                remote_ip=remote,
                user_agent=wanted["user-agent"] or None,
            )
            tx._token = _active_transaction.set(tx)
            return tx
        except Exception:
            logger.exception("failed to start request transaction")
            return None

    def _finish_request(self, scope, tx, status, start, error):
        try:
            bucket = (f"{status // 100}xx"
                      if isinstance(status, int) and 100 <= status <= 599
                      else "unknown")
            method = str(scope.get("method") or "GET")
            if tx is not None:
                # Starlette/FastAPI put the matched route on the scope after
                # routing; its template path is the low-cardinality name.
                route_path = getattr(scope.get("route"), "path", None)
                if isinstance(route_path, str) and route_path:
                    tx.name = f"{method} {route_path}"[:MAX_NAME_LENGTH]
                if status is not None:
                    tx.set_http(status_code=status)
            tags = {"method": method, "status": bucket}
            _record(self.name, "timer", tags, "ms",
                    (time.perf_counter() - start) * 1000.0)
            _record("http.requests", "counter", tags, None, 1)
            if tx is None:
                return
            if error is not None:
                _capture_error(error, tx.name)
            try:
                _active_transaction.reset(tx._token)
            except ValueError:  # finished in a different context than started
                _active_transaction.set(None)
            outcome = "failed" if (error is not None or bucket == "5xx") else "success"
            _finish_transaction(tx, outcome)
        except Exception:
            logger.exception("failed to finish request transaction")


# Attribute names every LogRecord carries; anything else on a record is a
# user extra. Built from a probe record so it tracks the running Python.
_LOG_RECORD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", (), None))
) | {"message", "asctime", "taskName"}

_SECRET_ATTR_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|api[-_]?key|authorization"
    r"|credential|private[-_]?key|cookie|session)"
)


class RootTraceLogHandler(logging.Handler):
    """stdlib logging handler shipping records to RootTrace.

    Batches records in memory (cap 500, drop-oldest) and POSTs them to
    <api_url>/logs/ingest on the wrapper's existing flush cadence, with the
    same token auth. Messages are truncated at 8KB; record extras ride along
    as `attrs` with obvious secret-looking keys redacted. Never raises from
    emit()."""

    def __init__(self, apm, level=logging.NOTSET):
        super().__init__(level)
        self.apm = apm

    def emit(self, record):
        try:
            if record.name == "roottrace_apm":
                return  # never feed the wrapper's own logging back into itself
            message = record.getMessage()
            # logging.exception attaches exc_info; a shipped error log without
            # its traceback is half a log, so it rides in the message the way
            # a StreamHandler would print it, inside the same 8KB cap.
            if record.exc_info and record.exc_info[0] is not None:
                message = f"{message}\n{''.join(traceback.format_exception(*record.exc_info))}"
            elif record.exc_text:
                message = f"{message}\n{record.exc_text}"
            entry = {
                "service": self.apm.service,
                "level": record.levelname,
                "message": message[:MAX_LOG_MESSAGE_LENGTH],
                "logger": record.name,
                "timestamp": datetime.datetime.fromtimestamp(
                    record.created, datetime.timezone.utc
                ).isoformat(),
            }
            tx = _current_transaction()
            if tx is not None:
                entry["trace_id"] = tx.trace_id
            attrs = {}
            for key, value in record.__dict__.items():
                if key in _LOG_RECORD_ATTRS or key.startswith("_"):
                    continue
                if _SECRET_ATTR_RE.search(key):
                    attrs[key] = "[REDACTED]"
                elif isinstance(value, (str, int, float, bool)) or value is None:
                    attrs[key] = value
                else:
                    attrs[key] = str(value)[:MAX_LOG_MESSAGE_LENGTH]
            if attrs:
                entry["attrs"] = attrs
            self.apm._record_log(entry)
        except Exception:
            self.handleError(record)
