from django.urls import path

from . import views

urlpatterns = [
    path("login", views.login),
    path("logs", views.logs),
    path("healthz", views.healthz),
]
