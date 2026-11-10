"""Bounded, read-only PromQL validation against the configured Prometheus API."""

import json
import os
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener


DEFAULT_PROMETHEUS_URL = "http://monitoring-prometheus.monitoring.svc.cluster.local:9090"
PROMETHEUS_URL = (
    os.getenv("PROMETHEUS_URL") or DEFAULT_PROMETHEUS_URL
).strip().rstrip("/")
PROMETHEUS_QUERY_TIMEOUT = "5s"
HTTP_TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 1_000_000

# Avoid environment-configured HTTP proxies for this in-cluster service call.
_opener = build_opener(ProxyHandler({}))


class PrometheusValidationUnavailable(RuntimeError):
    """Raised when a Prometheus validation request cannot be completed."""


def _send_query(request: Request) -> tuple[int, dict]:
    """Send a bounded request and decode a Prometheus API JSON response."""
    try:
        with _opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            http_status = response.getcode()
            raw_body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        http_status = exc.code
        try:
            raw_body = exc.read(MAX_RESPONSE_BYTES + 1)
        finally:
            exc.close()
    except (URLError, TimeoutError, socket.timeout, OSError):
        raise PrometheusValidationUnavailable(
            "Prometheus could not be reached or the query timed out."
        ) from None

    if len(raw_body) > MAX_RESPONSE_BYTES:
        raise PrometheusValidationUnavailable(
            "Prometheus returned a response that was too large to validate safely."
        )

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PrometheusValidationUnavailable(
            "Prometheus returned an invalid response."
        ) from None

    if not isinstance(payload, dict):
        raise PrometheusValidationUnavailable(
            "Prometheus returned an invalid response."
        )
    return http_status, payload


def _safe_error_message(payload: dict) -> str:
    """Return a compact, single-line message from the Prometheus API."""
    raw_message = payload.get("error")
    if not isinstance(raw_message, str) or not raw_message.strip():
        return "Prometheus rejected the expression."
    # Collapsing whitespace also removes control characters before displaying it.
    return " ".join(raw_message.split())[:500]


def validate_promql_expression(expression: str) -> dict:
    """Evaluate an instant query and report whether it can serve as an alert expression.

    This is a read-only query. It does not create, update, or delete a rule.
    Alerting rules require an instant-vector result; empty vectors are valid.
    """
    if not isinstance(expression, str):
        return {
            "valid": False,
            "kind": "invalid",
            "message": "PromQL expression must be text.",
            "result_type": None,
            "result_count": 0,
            "has_results": False,
        }

    expression = expression.strip()
    if not expression:
        return {
            "valid": False,
            "kind": "invalid",
            "message": "PromQL expression is required.",
            "result_type": None,
            "result_count": 0,
            "has_results": False,
        }
    if len(expression) > 4096:
        return {
            "valid": False,
            "kind": "invalid",
            "message": "PromQL expression must be 4096 characters or fewer.",
            "result_type": None,
            "result_count": 0,
            "has_results": False,
        }

    parsed_url = urlsplit(PROMETHEUS_URL)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise PrometheusValidationUnavailable(
            "Prometheus validation is not configured with a valid HTTP endpoint."
        )

    query_parameters = urlencode(
        {"query": expression, "timeout": PROMETHEUS_QUERY_TIMEOUT, "limit": "1000"}
    ).encode("utf-8")
    request = Request(
        f"{PROMETHEUS_URL}/api/v1/query",
        data=query_parameters,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Alert-Portal-PromQL-Validation/0.1.12",
        },
        method="POST",
    )
    http_status, payload = _send_query(request)

    api_status = payload.get("status")
    if api_status == "error":
        error_type = payload.get("errorType")
        message = _safe_error_message(payload)
        if error_type == "bad_data" or http_status == 400:
            return {
                "valid": False,
                "kind": "invalid",
                "message": message,
                "result_type": None,
                "result_count": 0,
                "has_results": False,
            }
        if error_type == "execution":
            return {
                "valid": False,
                "kind": "evaluation_error",
                "message": message,
                "result_type": None,
                "result_count": 0,
                "has_results": False,
            }
        if error_type in {"timeout", "canceled", "unavailable"} or http_status >= 500:
            raise PrometheusValidationUnavailable(
                "Prometheus could not complete the query or the query timed out."
            )
        raise PrometheusValidationUnavailable(
            "Prometheus could not complete the validation request."
        )

    if api_status != "success" or not 200 <= http_status < 300:
        raise PrometheusValidationUnavailable(
            f"Prometheus returned an unexpected HTTP status ({http_status})."
        )

    data = payload.get("data")
    if not isinstance(data, dict):
        raise PrometheusValidationUnavailable("Prometheus returned an invalid query result.")

    result_type = data.get("resultType")
    if result_type != "vector":
        label = "a scalar" if result_type == "scalar" else "a non-vector result"
        if result_type == "string":
            label = "a string"
        return {
            "valid": False,
            "kind": "invalid",
            "message": (
                "Alerting expressions must return an instant vector; "
                f"this expression returned {label}."
            ),
            "result_type": result_type,
            "result_count": 0,
            "has_results": False,
        }

    results = data.get("result")
    if not isinstance(results, list):
        raise PrometheusValidationUnavailable("Prometheus returned an invalid vector result.")

    return {
        "valid": True,
        "kind": "valid",
        "message": "PromQL expression is valid.",
        "result_type": "vector",
        "result_count": len(results),
        "has_results": bool(results),
        "result_limit": 1000,
    }



def query_prometheus_vector(expression: str, *, result_limit: int = 1000) -> list[dict]:
    """Run a bounded, read-only instant query and return its vector results.

    This helper is intended for server-authored queries such as dynamic label
    choices for built-in PromQL templates. Callers must not pass user-defined
    URLs or arbitrary request parameters.
    """
    parsed_url = urlsplit(PROMETHEUS_URL)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise PrometheusValidationUnavailable(
            "Prometheus validation is not configured with a valid HTTP endpoint."
        )

    parameters = urlencode({
        "query": expression,
        "timeout": PROMETHEUS_QUERY_TIMEOUT,
        "limit": str(max(1, min(int(result_limit), 1000))),
    }).encode("utf-8")
    request = Request(
        f"{PROMETHEUS_URL}/api/v1/query",
        data=parameters,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Alert-Portal-PromQL-Templates/0.1.12",
        },
        method="POST",
    )
    http_status, payload = _send_query(request)

    if payload.get("status") != "success" or not 200 <= http_status < 300:
        raise PrometheusValidationUnavailable(
            "Prometheus could not return the built-in template options."
        )

    data = payload.get("data")
    if not isinstance(data, dict) or data.get("resultType") != "vector":
        raise PrometheusValidationUnavailable(
            "Prometheus returned an unexpected response for template options."
        )

    results = data.get("result")
    if not isinstance(results, list):
        raise PrometheusValidationUnavailable(
            "Prometheus returned an invalid response for template options."
        )
    return results[:max(1, min(int(result_limit), 1000))]
