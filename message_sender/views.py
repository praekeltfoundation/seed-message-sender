from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.conf import settings
from django.contrib.auth.models import User
from django import forms
from rest_hooks.models import Hook
from rest_framework import viewsets, status, filters, mixins
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from .models import (
    Outbound, Inbound, OutboundSendFailure, Channel, InvalidMessage)
from .serializers import (OutboundSerializer, InboundSerializer,
                          JunebugInboundSerializer, HookSerializer,
                          CreateUserSerializer, OutboundSendFailureSerializer)
from .tasks import (send_message, fire_metric, ConcurrencyLimiter,
                    requeue_failed_tasks)
from seed_message_sender.utils import (
    get_available_metrics, get_identity_by_address, create_identity)
from seed_papertrail.decorators import papertrail
import django_filters

# Uncomment line below if scheduled metrics are added
# from .tasks import scheduled_metrics


class UserView(APIView):
    """ API endpoint that allows users creation and returns their token.
    Only admin users can do this to avoid permissions escalation.
    """
    permission_classes = (IsAdminUser,)

    def post(self, request):
        '''Create a user and token, given an email. If user exists just
        provide the token.'''
        serializer = CreateUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        try:
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            user = User.objects.create_user(email, email=email)
        token, created = Token.objects.get_or_create(user=user)

        return Response(
            status=status.HTTP_201_CREATED, data={'token': token.key})


class HookViewSet(viewsets.ModelViewSet):
    """
    Retrieve, create, update or destroy webhooks.
    """
    permission_classes = (IsAuthenticated,)
    queryset = Hook.objects.all()
    serializer_class = HookSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class MultipleField(forms.Field):
    widget = forms.MultipleHiddenInput

    def clean(self, value):
        if value is None:
            return None
        return [super(MultipleField, self).clean(v) for v in value]


class MultipleFilter(django_filters.Filter):
    field_class = MultipleField

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('lookup_type', 'in')
        super(MultipleFilter, self).__init__(*args, **kwargs)


class OutboundFilter(filters.FilterSet):
    before = django_filters.IsoDateTimeFilter(name="created_at",
                                              lookup_type='lte')
    after = django_filters.IsoDateTimeFilter(name="created_at",
                                             lookup_type='gte')
    to_addr = MultipleFilter(name='to_addr')
    to_identity = MultipleFilter(name='to_identity')

    class Meta:
        model = Outbound
        fields = ('version', 'vumi_message_id',
                  'delivered', 'attempts', 'metadata',
                  'created_at', 'updated_at',
                  'before', 'after')


class OutboundViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Outbound models to be viewed or edited.
    """
    permission_classes = (IsAuthenticated,)
    queryset = Outbound.objects.all()
    serializer_class = OutboundSerializer
    filter_class = OutboundFilter
    filter_backends = (filters.DjangoFilterBackend, filters.OrderingFilter)
    ordering_fields = ('created_at',)

    @papertrail.debug('api_outbound_create', sample=0.1)
    def create(self, *args, **kwargs):
        return super(OutboundViewSet, self).create(*args, **kwargs)


class InboundFilter(filters.FilterSet):
    from_addr = MultipleFilter(name='from_addr')
    from_identity = MultipleFilter(name='from_identity')

    class Meta:
        model = Inbound
        fields = (
            'message_id', 'in_reply_to', 'to_addr', 'content',
            'transport_name', 'transport_type', 'created_at', 'updated_at',)


class InboundViewSet(viewsets.ModelViewSet):

    """
    API endpoint that allows Inbound models to be viewed or edited.
    """
    permission_classes = (IsAuthenticated,)
    queryset = Inbound.objects.all()
    filter_class = InboundFilter
    filter_backends = (filters.DjangoFilterBackend, filters.OrderingFilter)
    ordering_fields = ('created_at',)

    def get_serializer_class(self):
        if self.action == 'create':
            if "channel_data" in self.request.data:
                return JunebugInboundSerializer
        return InboundSerializer

    def create(self, request, *args, **kwargs):
        if not kwargs.get('channel_id'):
            channel = Channel.objects.get(default=True)
        else:
            channel = Channel.objects.get(channel_id=kwargs.get('channel_id'))

        if "from" in request.data:
            msisdn = request.data.pop("from")
        elif "from_addr" in request.data:
            msisdn = request.data.pop("from_addr")

        result = get_identity_by_address(msisdn)

        if result:
            identity_id = result['results'][0]['id']
        else:
            identity = {
                'details': {
                    'default_addr_type': 'msisdn',
                    'addresses': {
                        'msisdn': {
                            msisdn: {'default': True}
                        }
                    }
                }
            }
            identity = create_identity(identity)
            identity_id = identity['id']

        request.data['from_identity'] = identity_id

        if channel.concurrency_limit == 0:
            return super(InboundViewSet, self).create(request, *args, **kwargs)

        close_event = False
        # Handle message from Junebug
        if request.data.get("channel_data", {}).get("session_event", None) == \
                "close":
            close_event = True
            related_outbound = request.data["reply_to"]
        elif "session_event" in request.data:  # Handle message from Vumi
            if request.data["session_event"] == "close":
                close_event = True
                related_outbound = request.data["in_reply_to"]

        if close_event:
            if related_outbound is not None:
                try:
                    message = Outbound.objects.get(
                        vumi_message_id=related_outbound)
                except (ObjectDoesNotExist, MultipleObjectsReturned):
                    message = Outbound.objects.filter(
                        to_identity=identity_id).order_by('-created_at').last()
            else:
                message = Outbound.objects.filter(
                    to_identity=identity_id).order_by('-created_at').last()
            if message:
                ConcurrencyLimiter.decr_message_count(
                    channel, message.last_sent_time)

        return super(InboundViewSet, self).create(request, *args, **kwargs)


def fire_delivery_hook(outbound):
    outbound.refresh_from_db()
    # Only fire if the message has been delivered or we've reached max attempts
    if (not outbound.delivered and
            outbound.attempts < settings.MESSAGE_SENDER_MAX_RETRIES):
        return

    payload = {
        'outbound_id': str(outbound.id),
        'delivered': outbound.delivered,
        'to_addr': outbound.to_addr,
    }
    if hasattr(outbound, 'to_identity'):
        payload['identity'] = outbound.to_identity

    if payload['to_addr'] is None and payload.get('identity', None) is None:
        raise InvalidMessage(outbound)

    # Becaues the Junebug event endpoint has no authentication, we get an
    # AnonymousUser object for the user. So we have to manually find all of the
    # hook events, ignoring the user, and deliver them.
    hooks = Hook.objects.filter(event='outbound.delivery_report')
    for hook in hooks:
        hook.deliver_hook(None, payload_override={
            'hook': hook.dict(),
            'data': payload,
            }
        )


def decr_message_count(message):
    if message.channel:
        channel = message.channel
    else:
        channel = Channel.objects.get(default=True)
    ConcurrencyLimiter.decr_message_count(
        channel, message.last_sent_time)


class EventListener(APIView):

    """
    Triggers updates to outbound messages based on event data from Vumi
    """
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        """
        Checks for expect event types before continuing
        """

        try:
            expect = ["message_type", "event_type", "user_message_id",
                      "event_id", "timestamp"]
            if set(expect).issubset(request.data.keys()):
                # Load message
                message = Outbound.objects.select_related('channel').get(
                    vumi_message_id=request.data["user_message_id"])
                # only expecting `event` on this endpoint
                if request.data["message_type"] == "event":
                    event = request.data["event_type"]
                    # expecting ack, nack, delivery_report
                    if event == "ack":
                        message.delivered = True
                        message.to_addr = ''
                        message.metadata["ack_timestamp"] = \
                            request.data["timestamp"]
                        message.save()
                        fire_delivery_hook(message)

                        # OBD number of successful tries metric
                        if "voice_speech_url" in message.metadata:
                            fire_metric.apply_async(kwargs={
                                "metric_name":
                                    'vumimessage.obd.successful.sum',
                                "metric_value": 1.0
                            })
                    elif event == "delivery_report":
                        message.delivered = True
                        message.to_addr = ''
                        message.metadata["delivery_timestamp"] = \
                            request.data["timestamp"]
                        message.save()
                        fire_delivery_hook(message)
                    elif event == "nack":
                        if "nack_reason" in request.data:
                            message.metadata["nack_reason"] = \
                                request.data["nack_reason"]
                            message.save()
                        fire_delivery_hook(message)

                        decr_message_count(message)

                        send_message.delay(str(message.id))
                        if "voice_speech_url" in message.metadata:
                            fire_metric.apply_async(kwargs={
                                "metric_name":
                                    'vumimessage.obd.unsuccessful.sum',
                                "metric_value": 1.0
                            })

                    # Return
                    status = 200
                    accepted = {"accepted": True}
                else:
                    status = 400
                    accepted = {"accepted": False,
                                "reason": "Unexpected message_type"}
            else:
                status = 400
                accepted = {"accepted": False,
                            "reason": "Missing expected body keys"}
        except ObjectDoesNotExist:
            status = 400
            accepted = {"accepted": False,
                        "reason": "Missing message in control"}
        return Response(accepted, status=status)

    # TODO make this work in test harness, works in production
    # def perform_create(self, serializer):
    #     serializer.save(created_by=self.request.user,
    #                     updated_by=self.request.user)
    #
    # def perform_update(self, serializer):
    #     serializer.save(updated_by=self.request.user)


class JunebugEventListener(APIView):

    """
    Triggers updates to outbound messages based on event data from Junebug
    """
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        """
        Updates the message from the event data.
        """
        expect = ["event_type", "message_id", "timestamp"]
        if not set(expect).issubset(request.data.keys()):
            return Response({
                "accepted": False,
                "reason": "Missing expected body keys"
            }, status=400)

        try:
            message = Outbound.objects.select_related('channel').get(
                vumi_message_id=request.data["message_id"])
        except ObjectDoesNotExist:
            return Response({
                "accepted": False,
                "reason": "Cannot find message for event"
            }, status=400)

        event_type = request.data["event_type"]
        if event_type == "submitted":
            message.delivered = True
            message.to_addr = ''
            message.metadata["ack_timestamp"] = request.data["timestamp"]
            message.save(update_fields=['metadata', 'delivered', 'to_addr'])
            fire_delivery_hook(message)

            # OBD number of successful tries metric
            if "voice_speech_url" in message.metadata:
                fire_metric.apply_async(kwargs={
                    "metric_name": 'vumimessage.obd.successful.sum',
                    "metric_value": 1.0
                })
        elif event_type == "rejected":
            message.metadata["nack_reason"] = (
                request.data.get("event_details"))
            message.save(update_fields=['metadata'])
            fire_delivery_hook(message)
            decr_message_count(message)
            send_message.delay(str(message.id))
        elif event_type == "delivery_succeeded":
            message.delivered = True
            message.to_addr = ''
            message.metadata["delivery_timestamp"] = request.data["timestamp"]
            message.save(update_fields=['delivered', 'metadata', 'to_addr'])
            fire_delivery_hook(message)
        elif event_type == "delivery_failed":
            message.metadata["delivery_failed_reason"] = (
                request.data.get("event_details"))
            message.save(update_fields=['metadata'])
            fire_delivery_hook(message)
            decr_message_count(message)
            send_message.delay(str(message.id))

        if ("voice_speech_url" in message.metadata and
                event_type in ("rejected", "delivery_failed")):
            fire_metric.apply_async(kwargs={
                "metric_name": 'vumimessage.obd.unsuccessful.sum',
                "metric_value": 1.0
            })

        return Response({"accepted": True}, status=200)


class MetricsView(APIView):

    """ Metrics Interaction
        GET - returns list of all available metrics on the service
        POST - starts up the task that fires all the scheduled metrics
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        status = 200
        resp = {
            "metrics_available": get_available_metrics()
        }
        return Response(resp, status=status)

    def post(self, request, *args, **kwargs):
        status = 201
        # Uncomment line below if scheduled metrics are added
        # scheduled_metrics.apply_async()
        resp = {"scheduled_metrics_initiated": True}
        return Response(resp, status=status)


class HealthcheckView(APIView):

    """ Healthcheck Interaction
        GET - returns service up - getting auth'd requires DB
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        import seed_message_sender
        import django
        import rest_framework
        status = 200
        resp = {
            "up": True,
            "result": {
                "database": "Accessible",
                "version": seed_message_sender.__version__,
                "libraries": {
                    "django": django.__version__,
                    "djangorestframework": rest_framework.__version__
                }
            }
        }
        return Response(resp, status=status)


class FailedTaskViewSet(mixins.ListModelMixin,
                        mixins.RetrieveModelMixin,
                        viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = OutboundSendFailure.objects.all()
    serializer_class = OutboundSendFailureSerializer

    def create(self, request):
        status = 201
        resp = {'requeued_failed_tasks': True}
        requeue_failed_tasks.delay()
        return Response(resp, status=status)
