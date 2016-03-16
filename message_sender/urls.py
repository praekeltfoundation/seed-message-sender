from django.conf.urls import url, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'inbound', views.InboundViewSet)
router.register(r'outbound', views.OutboundViewSet)
router.register(r'webhook', views.HookViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browseable API.
urlpatterns = [
    url('^api/v1/events$',
        views.EventListener.as_view()),
    url(r'^api/v1/', include(router.urls)),
]
