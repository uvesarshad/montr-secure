"""URLConf (corpus: python-clean)."""
from django.urls import path

from . import views

urlpatterns = [
    path("search/", views.user_search, name="user-search"),
    path("orders/<int:order_id>/", views.order_detail, name="order-detail"),
]
