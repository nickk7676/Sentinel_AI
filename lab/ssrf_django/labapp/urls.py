from django.urls import path

from . import views

urlpatterns = [
    path("welcome", views.welcome),
    path("preview", views.preview),
    path("logs", views.logs),
    path("healthz", views.healthz),
]
