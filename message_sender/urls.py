from django.conf.urls import url, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'inbound', views.InboundViewSet)
router.register(r'outbound', views.OutboundViewSet)
router.register(r'webhook', views.HookViewSet)
router.register(r'failed-tasks', views.FailedTaskViewSet)
router.register(r'aggregate-outbounds', views.AggregateOutboundViewSet)
router.register(r'archive-outbounds', views.ArchivedOutboundViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browseable API.
urlpatterns = [
    url('^api/v1/events$',
        views.EventListener.as_view()),
    url(
        '^api/v1/events/junebug$', views.JunebugEventListener.as_view(),
        name='junebug-events'),
    url(
        r'^api/v1/events/wassup$',
        views.WassupEventListener.as_view(),
        name='wassup-events'),
    url(r'^api/v1/user/token/$', views.UserView.as_view(),
        name='create-user-token'),
    url(r'^api/v1/inbound/(?P<channel_id>\w+)/$',
        views.InboundViewSet.as_view({'post': 'create'}),
        name='channels-inbound'),
    url(r'^api/v1/', include(router.urls)),
]
