from django.urls import path

from . import views

urlpatterns = [
    path("diagnostics", views.diagnostics),
    path("logs", views.logs),
    path("healthz", views.healthz),
]
