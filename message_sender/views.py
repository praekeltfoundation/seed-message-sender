from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from rest_hooks.models import Hook
from rest_framework import viewsets, status, filters
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from requests.exceptions import HTTPError

from .models import Outbound, Inbound
from django.contrib.auth.models import User
from .factory import MessageClientFactory
from .serializers import (OutboundSerializer, InboundSerializer,
                          JunebugInboundSerializer, HookSerializer,
                          CreateUserSerializer)
from .tasks import send_message, fire_metric, ConcurrencyLimiter
from seed_message_sender.utils import get_available_metrics, load_callable
import django_filters


voice_to_addr_formatter = load_callable(settings.VOICE_TO_ADDR_FORMATTER)

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


class OutboundFilter(filters.FilterSet):
    before = django_filters.IsoDateTimeFilter(name="created_at",
                                              lookup_type='lte')
    after = django_filters.IsoDateTimeFilter(name="created_at",
                                             lookup_type='gte')

    class Meta:
        model = Outbound
        fields = ('version', 'to_addr', 'vumi_message_id',
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


class InboundViewSet(viewsets.ModelViewSet):

    """
    API endpoint that allows Inbound models to be viewed or edited.
    """
    permission_classes = (IsAuthenticated,)
    queryset = Inbound.objects.all()
    filter_fields = ('message_id', 'in_reply_to', 'to_addr', 'from_addr',
                     'content', 'transport_name', 'transport_type',
                     'helper_metadata', 'created_at', 'updated_at',)

    def get_serializer_class(self):
        if self.action == 'create':
            if "channel_data" in self.request.data:
                return JunebugInboundSerializer
        return InboundSerializer

    def create(self, request, *args, **kwargs):
        close_event = False
        if "channel_data" in request.data:  # Handle message from Junebug
            if "session_event" in request.data["channel_data"]:
                if request.data["channel_data"]["session_event"] == "close":
                    close_event = True
                    reply_field = "reply_to"
                    from_field = "from"
        elif "session_event" in request.data:  # Handle message from Vumi
            if request.data["session_event"] == "close":
                close_event = True
                reply_field = "in_reply_to"
                from_field = "from_addr"

        if close_event:
            try:
                message = Outbound.objects.get(
                    vumi_message_id=request.data[reply_field])
            except ObjectDoesNotExist:
                message = Outbound.objects.filter(
                    to_addr=request.data[from_field]).order_by(
                    '-created_at').last()
            if message:
                outbound_type = "voice" if "voice_speech_url" in \
                    message.metadata else "text"
                ConcurrencyLimiter.decr_message_count(
                    outbound_type, message.last_sent_time)

        return super(InboundViewSet, self).create(request, *args, **kwargs)


class EventListener(APIView):

    """
    Triggers updates to outbound messages based on event data from Vumi
    """
    permission_classes = (AllowAny,)

    def _handle_voice_ack(self, message, timestamp):
        if message.call_answered:
            message.delivered = True
            message.metadata["ack_timestamp"] = timestamp
            message.save(update_fields=['delivered', 'metadata'])
            fire_metric.apply_async(kwargs={
                "metric_name":
                    'vumimessage.obd.successful.sum',
                "metric_value": 1.0
            })
        else:
            message.call_answered = True
            message.metadata["call_answered_timestamp"] = timestamp

            client = MessageClientFactory.create('voice')
            speech_url = message.metadata['voice_speech_url']
            try:
                vumiresponse = client.send_voice(
                    voice_to_addr_formatter(message.to_addr), message.content,
                    speech_url=speech_url, session_event="close")
            except HTTPError:
                message.save(update_fields=['metadata'])
                send_message.delay(message_id=str(message.id))
                return

            message.vumi_message_id = vumiresponse["message_id"]
            message.save(update_fields=[
                'call_answered', 'metadata', 'vumi_message_id'])

    def _handle_text_ack(self, message, timestamp):
        message.delivered = True
        message.metadata["ack_timestamp"] = timestamp
        message.save(update_fields=['delivered', 'metadata'])

    def post(self, request, *args, **kwargs):
        """
        Checks for expect event types before continuing
        """

        try:
            expect = ["message_type", "event_type", "user_message_id",
                      "event_id", "timestamp"]
            if set(expect).issubset(request.data.keys()):
                # Load message
                message = Outbound.objects.get(
                    vumi_message_id=request.data["user_message_id"])
                # only expecting `event` on this endpoint
                if request.data["message_type"] == "event":
                    event = request.data["event_type"]
                    # expecting ack, nack, delivery_report
                    if event == "ack":
                        if "voice_speech_url" in message.metadata:
                            self._handle_voice_ack(
                                message, request.data['timestamp'])
                        else:
                            self._handle_text_ack(
                                message, request.data['timestamp'])
                    elif event == "delivery_report":
                        message.delivered = True
                        message.metadata["delivery_timestamp"] = \
                            request.data["timestamp"]
                        message.save()
                    elif event == "nack":
                        if "nack_reason" in request.data:
                            message.metadata["nack_reason"] = \
                                request.data["nack_reason"]
                            message.save()
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


class JunebugEventListener(EventListener):

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
            message = Outbound.objects.get(
                vumi_message_id=request.data["message_id"])
        except ObjectDoesNotExist:
            return Response({
                "accepted": False,
                "reason": "Cannot find message for event"
            }, status=400)

        event_type = request.data["event_type"]
        if event_type == "submitted":
            if "voice_speech_url" in message.metadata:
                self._handle_voice_ack(message, request.data["timestamp"])
            else:
                self._handle_text_ack(message, request.data["timestamp"])
        elif event_type == "rejected":
            message.metadata["nack_reason"] = (
                request.data.get("event_details"))
            message.save(update_fields=['metadata'])
            send_message.delay(str(message.id))
        elif event_type == "delivery_succeeded":
            message.delivered = True
            message.metadata["delivery_timestamp"] = request.data["timestamp"]
            message.save(update_fields=['delivered', 'metadata'])
        elif event_type == "delivery_failed":
            message.metadata["delivery_failed_reason"] = (
                request.data.get("event_details"))
            message.save(update_fields=['metadata'])
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
