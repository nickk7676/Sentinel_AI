from django.urls import path

from . import views

urlpatterns = [
    path("download", views.download),
    path("logs", views.logs),
    path("healthz", views.healthz),
]
