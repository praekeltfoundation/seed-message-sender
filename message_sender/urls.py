from django.conf.urls import url
from django.urls import include, path
from rest_framework import routers

from . import views

router = routers.DefaultRouter()
router.register(r"inbound", views.InboundViewSet)
router.register(r"outbound", views.OutboundViewSet)
router.register(r"webhook", views.HookViewSet)
router.register(r"failed-tasks", views.FailedTaskViewSet)
router.register(r"aggregate-outbounds", views.AggregateOutboundViewSet)
router.register(r"archive-outbounds", views.ArchivedOutboundViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browseable API.
urlpatterns = [
    path("api/v1/events", views.EventListener.as_view()),
    path(
        "api/v1/events/junebug",
        views.JunebugEventListener.as_view(),
        name="junebug-events",
    ),
    path(
        "api/v1/events/wassup",
        views.WassupEventListener.as_view(),
        name="wassup-events",
    ),
    path(
        "api/v1/events/whatsapp/<channel_id>",
        views.WhatsAppEventListener.as_view(),
        name="whatsapp-events",
    ),
    path("api/v1/user/token/", views.UserView.as_view(), name="create-user-token"),
    url(
        "^api/v1/inbound/(?P<channel_id>\w+)/$",
        views.InboundViewSet.as_view({"post": "create"}),
        name="channels-inbound",
    ),
    path("api/v1/", include(router.urls)),
]
