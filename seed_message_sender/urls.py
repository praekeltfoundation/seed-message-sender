import os
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from message_sender import views
from django_prometheus import exports as django_prometheus
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.documentation import include_docs_urls
from seed_message_sender.decorators import internal_only

admin.site.site_header = os.environ.get(
    "MESSAGE_SENDER_TITLE", "Seed Message Sender Admin"
)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("rest_framework.urls", namespace="rest_framework")),
    path("api/token-auth/", obtain_auth_token),
    path("api/metrics/", views.MetricsView.as_view()),
    path("api/health/", views.HealthcheckView.as_view()),
    path("", include("message_sender.urls")),
    path("docs/", include_docs_urls()),
    path(
        "metrics", internal_only(django_prometheus.ExportToDjangoView), name="metrics"
    ),
]


if settings.DEBUG is True:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
