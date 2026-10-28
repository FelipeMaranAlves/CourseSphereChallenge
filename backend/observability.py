import json
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Tuple
from flask import Flask, Response, g, jsonify, request
from db import execute_query

INSTANCE_ID = os.getenv("INSTANCE_ID", socket.gethostname())
START_TIME = time.time()

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.3, 0.5, 1.0, 2.5, 5.0)


class JSONFormatter(logging.Formatter):
    """
    Formats log records as single-line structured JSON objects for SRE observability.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "coursesphere-backend",
            "instance_id": INSTANCE_ID,
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
        }
        extra_fields = getattr(record, "extra_fields", None)
        if isinstance(extra_fields, dict):
            payload.update(extra_fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_structured_logging(app: Flask) -> logging.Logger:
    logger = logging.getLogger("coursesphere")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    app.logger.handlers = logger.handlers
    app.logger.setLevel(logging.INFO)
    return logger


class PrometheusMetrics:
    """
    Thread-safe Prometheus metrics collector exposing counters, histograms, and gauges.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests_total: Dict[Tuple[str, str, int], int] = {}
        self.errors_5xx_total: Dict[str, int] = {}
        self.auth_failures_total: Dict[str, int] = {}
        self.latency_sum: Dict[str, float] = {}
        self.latency_count: Dict[str, int] = {}
        self.latency_buckets: Dict[Tuple[str, float], int] = {}

    def observe_request(
        self, method: str, endpoint: str, status_code: int, duration_seconds: float
    ) -> None:
        with self._lock:
            req_key = (method, endpoint, status_code)
            self.requests_total[req_key] = self.requests_total.get(req_key, 0) + 1

            if status_code >= 500:
                self.errors_5xx_total[endpoint] = (
                    self.errors_5xx_total.get(endpoint, 0) + 1
                )

            self.latency_sum[endpoint] = (
                self.latency_sum.get(endpoint, 0.0) + duration_seconds
            )
            self.latency_count[endpoint] = self.latency_count.get(endpoint, 0) + 1

            for bound in LATENCY_BUCKETS:
                if duration_seconds <= bound:
                    b_key = (endpoint, bound)
                    self.latency_buckets[b_key] = (
                        self.latency_buckets.get(b_key, 0) + 1
                    )

    def record_auth_failure(self, reason: str) -> None:
        with self._lock:
            self.auth_failures_total[reason] = (
                self.auth_failures_total.get(reason, 0) + 1
            )

    def render_prometheus_text(self) -> str:
        lines = [
            "# HELP process_uptime_seconds Uptime of the backend instance in seconds.",
            "# TYPE process_uptime_seconds gauge",
            f'process_uptime_seconds{{instance="{INSTANCE_ID}"}} {time.time() - START_TIME:.2f}',
            "# HELP http_requests_total Total number of HTTP requests processed.",
            "# TYPE http_requests_total counter",
        ]
        with self._lock:
            for (method, endpoint, status), count in sorted(
                self.requests_total.items()
            ):
                lines.append(
                    f'http_requests_total{{method="{method}",endpoint="{endpoint}",status="{status}",instance="{INSTANCE_ID}"}} {count}'
                )

            lines.append(
                "# HELP http_errors_5xx_total Total number of HTTP 5xx server error responses."
            )
            lines.append("# TYPE http_errors_5xx_total counter")
            for endpoint, count in sorted(self.errors_5xx_total.items()):
                lines.append(
                    f'http_errors_5xx_total{{endpoint="{endpoint}",instance="{INSTANCE_ID}"}} {count}'
                )

            lines.append(
                "# HELP auth_failures_total Total number of authentication failures."
            )
            lines.append("# TYPE auth_failures_total counter")
            for reason, count in sorted(self.auth_failures_total.items()):
                lines.append(
                    f'auth_failures_total{{reason="{reason}",instance="{INSTANCE_ID}"}} {count}'
                )

            lines.append(
                "# HELP http_request_duration_seconds HTTP request latency histogram in seconds."
            )
            lines.append("# TYPE http_request_duration_seconds histogram")
            for endpoint, total_count in sorted(self.latency_count.items()):
                for bound in LATENCY_BUCKETS:
                    b_count = self.latency_buckets.get((endpoint, bound), 0)
                    lines.append(
                        f'http_request_duration_seconds_bucket{{endpoint="{endpoint}",instance="{INSTANCE_ID}",le="{bound}"}} {b_count}'
                    )
                lines.append(
                    f'http_request_duration_seconds_bucket{{endpoint="{endpoint}",instance="{INSTANCE_ID}",le="+Inf"}} {total_count}'
                )
                total_sum = self.latency_sum.get(endpoint, 0.0)
                lines.append(
                    f'http_request_duration_seconds_sum{{endpoint="{endpoint}",instance="{INSTANCE_ID}"}} {total_sum:.6f}'
                )
                lines.append(
                    f'http_request_duration_seconds_count{{endpoint="{endpoint}",instance="{INSTANCE_ID}"}} {total_count}'
                )
        return "\n".join(lines) + "\n"


metrics = PrometheusMetrics()


def log_event(
    logger: logging.Logger, level: int, event: str, message: str, **fields
) -> None:
    logger.log(
        level,
        message,
        extra={"event": event, "extra_fields": fields},
    )


def register_observability(app: Flask) -> logging.Logger:
    logger = configure_structured_logging(app)

    @app.before_request
    def start_timer():
        g.request_start_time = time.perf_counter()

    @app.after_request
    def record_observability(response: Response) -> Response:
        start = getattr(g, "request_start_time", None)
        duration_sec = (time.perf_counter() - start) if start is not None else 0.0
        duration_ms = round(duration_sec * 1000.0, 2)
        endpoint = request.url_rule.rule if request.url_rule else request.path

        response.headers["X-Instance-ID"] = INSTANCE_ID
        response.headers["X-Response-Time-Ms"] = str(duration_ms)

        metrics.observe_request(
            request.method, endpoint, response.status_code, duration_sec
        )

        log_event(
            logger,
            logging.INFO if response.status_code < 400 else logging.WARNING,
            "http_request",
            f"{request.method} {request.path} -> {response.status_code}",
            method=request.method,
            path=request.path,
            endpoint=endpoint,
            status_code=response.status_code,
            duration_ms=duration_ms,
            client_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            user_uid=getattr(g, "user_uid", None),
        )
        return response

    @app.route("/health", methods=["GET"])
    def health_check():
        try:
            execute_query("SELECT 1")
            db_status = "connected"
            status_code = 200
            overall = "healthy"
        except Exception as exc:
            log_event(
                logger,
                logging.ERROR,
                "healthcheck_failure",
                "Database connectivity check failed",
                error=str(exc),
            )
            db_status = "disconnected"
            status_code = 503
            overall = "degraded"

        return (
            jsonify(
                {
                    "status": overall,
                    "service": "coursesphere-backend",
                    "instance_id": INSTANCE_ID,
                    "database": db_status,
                    "uptime_seconds": round(time.time() - START_TIME, 2),
                }
            ),
            status_code,
        )

    @app.route("/metrics", methods=["GET"])
    def prometheus_metrics():
        return Response(
            metrics.render_prometheus_text(),
            status=200,
            mimetype="text/plain; version=0.0.4; charset=utf-8",
        )

    return logger

