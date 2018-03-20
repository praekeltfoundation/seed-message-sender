import os
from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static
from django.contrib import admin
from message_sender import views
from rest_framework.authtoken.views import obtain_auth_token

admin.site.site_header = os.environ.get('MESSAGE_SENDER_TITLE',
                                        'Seed Message Sender Admin')


urlpatterns = [
    url(r'^admin/',  include(admin.site.urls)),
    url(r'^api/auth/',
        include('rest_framework.urls', namespace='rest_framework')),
    url(r'^api/token-auth/', obtain_auth_token),
    url(r'^api/metrics/', views.MetricsView.as_view()),
    url(r'^api/health/', views.HealthcheckView.as_view()),
    url(r'^', include('message_sender.urls')),
    url(r'^docs/', include('rest_framework_docs.urls')),
]


if settings.DEBUG is True:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT,
    )
