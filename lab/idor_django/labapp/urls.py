from django.urls import path

from . import views

urlpatterns = [
    path("login", views.login),
    path("api/tickets/<int:ticket_id>", views.get_ticket),
    path("logs", views.logs),
    path("healthz", views.healthz),
]
