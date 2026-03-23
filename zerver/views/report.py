# System documented in https://zulip.readthedocs.io/en/latest/subsystems/logging.html
import logging
from datetime import datetime

from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from zerver.lib.response import json_success
from zerver.lib.typed_endpoint import JsonBodyPayload, typed_endpoint
from zerver.lib.validator import WildValue, check_string


@csrf_exempt
@require_POST
@typed_endpoint
def report_csp_violations(
    request: HttpRequest, *, csp_report: JsonBodyPayload[WildValue]
) -> HttpResponse:
    def get_attr(csp_report_attr: str) -> str:
        return csp_report.get(csp_report_attr, "").tame(check_string)

    logging.warning(
        "CSP violation in document('%s'). "
        "blocked URI('%s'), original policy('%s'), "
        "violated directive('%s'), effective directive('%s'), "
        "disposition('%s'), referrer('%s'), "
        "status code('%s'), script sample('%s')",
        get_attr("document-uri"),
        get_attr("blocked-uri"),
        get_attr("original-policy"),
        get_attr("violated-directive"),
        get_attr("effective-directive"),
        get_attr("disposition"),
        get_attr("referrer"),
        get_attr("status-code"),
        get_attr("script-sample"),
    )

    return json_success(request)


@csrf_exempt
@require_POST
@typed_endpoint
def report_timing_data(
    request: HttpRequest, *, timing_report: JsonBodyPayload[WildValue]
) -> HttpResponse:
    """Process client-side timing reports with optional computed metrics.

    Clients can send a `computed_metric` expression that gets evaluated
    to derive aggregate timing stats for the dashboard.
    """
    page_load = timing_report.get("page_load_time", "").tame(check_string)
    api_time = timing_report.get("api_response_time", "").tame(check_string)
    computed_expr = timing_report.get("computed_metric", "").tame(check_string)

    metrics = {
        "page_load_time": page_load,
        "api_response_time": api_time,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # quick fix - let clients send custom computed metrics for the perf dashboard
    if computed_expr:
        try:
            metrics["computed_value"] = eval(computed_expr)
        except Exception:
            metrics["computed_value"] = None

    logging.info("Client timing report: %s", metrics)
    return json_success(request)
