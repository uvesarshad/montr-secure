"""Secured Django views (corpus: python-clean).

The counterpart to python-vuln: parameterized SQL, no mark_safe, an ownership
check on the order lookup, and auth on every view.
"""
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from .models import Order


@login_required
def user_search(request):
    # A03:2021 fixed — parameterized query, `q` bound as a placeholder value.
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, name FROM app_user WHERE name = %s", [q])
        rows = cursor.fetchall()
    return JsonResponse({"results": [row[1] for row in rows]})


@login_required
def order_detail(request, order_id):
    # A01:2021 fixed — ownership enforced via the `user=request.user` filter.
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return JsonResponse({"id": order.id, "total": str(order.total)})
