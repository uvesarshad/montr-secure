"""URLConf (corpus: python-vuln)."""
from django.urls import path, re_path

from . import views

urlpatterns = [
    path("search/", views.user_search, name="user-search"),
    path("fetch/", views.fetch_preview, name="fetch-preview"),
    re_path(r"^orders/(?P<order_id>\d+)/$", views.order_detail, name="order-detail"),
]
