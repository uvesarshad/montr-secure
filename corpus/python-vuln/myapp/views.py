"""Intentionally vulnerable Django views (corpus: python-vuln). DO NOT DEPLOY.

Planted OWASP issues for the golden-corpus regression gate:
SQL injection, reflected XSS, SSRF, and IDOR.
"""
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.utils.safestring import mark_safe
import requests

from .models import Order


def user_search(request):
    # A03:2021 — SQL Injection: tainted `q` interpolated straight into raw SQL.
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, name FROM app_user WHERE name = '{q}'")
        rows = cursor.fetchall()
    # A03:2021 — Reflected XSS: `q` echoed via mark_safe (autoescaping bypassed).
    html = mark_safe(f"<h1>Results for {q}</h1>")
    return HttpResponse(html)


def fetch_preview(request):
    # A10:2021 — SSRF: the server fetches an attacker-controlled URL, no allowlist.
    target = request.GET.get("url")
    resp = requests.get(target, timeout=5)
    return HttpResponse(resp.content)


def order_detail(request, order_id):
    # A01:2021 — IDOR: order fetched by id with no ownership check.
    order = Order.objects.get(id=order_id)
    return JsonResponse({"id": order.id, "total": str(order.total)})
