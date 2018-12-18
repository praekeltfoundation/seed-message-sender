import base64
import hmac
from datetime import datetime, timedelta
from hashlib import sha256

from django import forms
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from prometheus_client import Counter
from rest_framework import mixins, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.filters import OrderingFilter
from rest_framework.pagination import CursorPagination
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_hooks.models import Hook

from seed_message_sender.utils import (
    create_identity,
    get_available_metrics,
    get_identity_by_address,
)

from .formatters import e_164
from .models import (
    AggregateOutbounds,
    ArchivedOutbounds,
    Channel,
    Inbound,
    InvalidMessage,
    Outbound,
    OutboundSendFailure,
)
from .serializers import (
    AggregateOutboundSerializer,
    ArchivedOutboundSerializer,
    CreateUserSerializer,
    EventSerializer,
    HookSerializer,
    InboundSerializer,
    JunebugEventSerializer,
    JunebugInboundSerializer,
    OutboundSendFailureSerializer,
    OutboundSerializer,
    WassupEventSerializer,
    WassupInboundSerializer,
    WhatsAppWebhookSerializer,
    WhatsAppEventSerializer,
    WhatsAppInboundSerializer,
)
from .tasks import (
    ConcurrencyLimiter,
    aggregate_outbounds,
    archive_outbound,
    requeue_failed_tasks,
    send_message,
)

# Uncomment line below if scheduled metrics are added
# from .tasks import scheduled_metrics


class IdCursorPagination(CursorPagination):
    ordering = "-id"


class UserView(APIView):
    """ API endpoint that allows users creation and returns their token.
    Only admin users can do this to avoid permissions escalation.
    """

    permission_classes = (IsAdminUser,)

    def post(self, request):
        """Create a user and token, given an email. If user exists just
        provide the token."""
        serializer = CreateUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get("email")
        try:
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            user = User.objects.create_user(email, email=email)
        token, created = Token.objects.get_or_create(user=user)

        return Response(status=status.HTTP_201_CREATED, data={"token": token.key})


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


class MultipleFilter(filters.Filter):
    field_class = MultipleField

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("lookup_expr", "in")
        super(MultipleFilter, self).__init__(*args, **kwargs)


class OutboundFilter(filters.FilterSet):
    before = filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="lte")
    after = filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="gte")
    to_addr = MultipleFilter(field_name="to_addr")
    to_identity = MultipleFilter(field_name="to_identity")

    class Meta:
        model = Outbound
        fields = (
            "version",
            "vumi_message_id",
            "delivered",
            "attempts",
            "created_at",
            "updated_at",
            "before",
            "after",
        )


class OutboundViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Outbound models to be viewed or edited.
    """

    permission_classes = (IsAuthenticated,)
    queryset = Outbound.objects.all()
    serializer_class = OutboundSerializer
    filterset_class = OutboundFilter
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)
    ordering_fields = ("created_at",)
    ordering = ("-created_at",)

    def create(self, *args, **kwargs):
        return super(OutboundViewSet, self).create(*args, **kwargs)


class InboundFilter(filters.FilterSet):
    from_addr = MultipleFilter(field_name="from_addr")
    from_identity = MultipleFilter(field_name="from_identity")

    class Meta:
        model = Inbound
        fields = (
            "message_id",
            "in_reply_to",
            "to_addr",
            "content",
            "transport_name",
            "transport_type",
            "created_at",
            "updated_at",
        )


class InboundPreprocessor(object):
    def pop_from_address(self, data, channel):
        if channel.channel_type == Channel.VUMI_TYPE:
            return data.pop("from_addr", None)
        elif channel.channel_type == Channel.JUNEBUG_TYPE:
            return data.pop("from", None)
        elif channel.channel_type == Channel.WASSUP_API_TYPE:
            return data.get("data", {}).pop("from_addr", None)
        elif channel.channel_type == Channel.WHATSAPP_API_TYPE:
            return data.pop("from", None)

    def is_close_event(self, data, channel):
        if channel.channel_type == Channel.VUMI_TYPE:
            return data.get("session_event") == "close"
        elif channel.channel_type == Channel.JUNEBUG_TYPE:
            return data.get("channel_data", {}).get("session_event") == "close"
        # Wassup/WhatsApp doesn't have sessions
        return False

    def get_related_outbound_id(self, data, channel):
        if channel.channel_type == Channel.VUMI_TYPE:
            return data.get("in_reply_to")
        elif channel.channel_type == Channel.JUNEBUG_TYPE:
            return data.get("reply_to")
        return None

    def get_or_create_identity(self, msisdn):
        result = get_identity_by_address(msisdn)

        if result:
            return result[0]["id"]
        else:
            return create_identity(
                {
                    "details": {
                        "default_addr_type": "msisdn",
                        "addresses": {"msisdn": {msisdn: {"default": True}}},
                    }
                }
            )["id"]

    def preprocess_inbound(self, data, channel):
        msisdn = self.pop_from_address(data, channel)
        if msisdn is None:
            return
        msisdn = e_164(msisdn)
        data["from_identity"] = self.get_or_create_identity(msisdn)

        if channel.concurrency_limit == 0:
            return

        related_outbound = self.get_related_outbound_id(data, channel)
        if self.is_close_event(data, channel) and related_outbound:
            try:
                message = Outbound.objects.get(vumi_message_id=related_outbound)
            except (ObjectDoesNotExist, MultipleObjectsReturned):
                message = (
                    Outbound.objects.filter(to_identity=data["from_identity"])
                    .order_by("-created_at")
                    .last()
                )
            if message:
                ConcurrencyLimiter.decr_message_count(channel, message.last_sent_time)


preprocess_inbound = InboundPreprocessor().preprocess_inbound


class InboundViewSet(viewsets.ModelViewSet):

    """
    API endpoint that allows Inbound models to be viewed or edited.
    """

    permission_classes = (IsAuthenticated,)
    queryset = Inbound.objects.all()
    filterset_class = InboundFilter
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)
    ordering_fields = ("created_at",)
    ordering = ("-created_at",)

    def get_serializer_class(self):
        if self.action == "create":
            if self.channel.channel_type == Channel.VUMI_TYPE:
                return InboundSerializer
            elif self.channel.channel_type == Channel.JUNEBUG_TYPE:
                return JunebugInboundSerializer
            elif self.channel.channel_type == Channel.WASSUP_API_TYPE:
                return WassupInboundSerializer
            elif self.channel.channel_type == Channel.WHATSAPP_API_TYPE:
                return WhatsAppInboundSerializer
        return InboundSerializer

    def create(self, request, *args, **kwargs):
        if not kwargs.get("channel_id"):
            self.channel = Channel.objects.get(default=True)
        else:
            self.channel = Channel.objects.get(channel_id=kwargs.get("channel_id"))

        preprocess_inbound(request.data, self.channel)
        return super(InboundViewSet, self).create(request, *args, **kwargs)


def fire_delivery_hook(outbound):
    outbound.refresh_from_db()
    # Only fire if the message has been delivered or we've reached max attempts
    if (
        not outbound.delivered
        and outbound.attempts < settings.MESSAGE_SENDER_MAX_RETRIES
    ):
        return

    payload = {
        "outbound_id": str(outbound.id),
        "delivered": outbound.delivered,
        "to_addr": outbound.to_addr,
    }
    if hasattr(outbound, "to_identity"):
        payload["identity"] = outbound.to_identity

    if payload["to_addr"] is None and payload.get("identity", None) is None:
        raise InvalidMessage(outbound)

    # Becaues the Junebug event endpoint has no authentication, we get an
    # AnonymousUser object for the user. So we have to manually find all of the
    # hook events, ignoring the user, and deliver them.
    hooks = Hook.objects.filter(event="outbound.delivery_report")
    for hook in hooks:
        hook.deliver_hook(None, payload_override={"hook": hook.dict(), "data": payload})


def decr_message_count(message):
    if message.channel:
        channel = message.channel
    else:
        channel = Channel.objects.get(default=True)
    ConcurrencyLimiter.decr_message_count(channel, message.last_sent_time)


outbound_event_total = Counter(
    "outbound_event_total", "Number of Outbound events", ["type", "channel"]
)


def process_event(message_id, event_type, event_detail, timestamp):
    """
    Processes an event of the given details, returning a (success, message) tuple
    """
    # Load message
    try:
        message = Outbound.objects.select_related("channel").get(
            vumi_message_id=message_id
        )
    except ObjectDoesNotExist:
        return (False, "Cannot find message for ID {}".format(message_id))

    if event_type == "ack":
        message.delivered = True
        message.to_addr = ""
        message.metadata["ack_timestamp"] = timestamp
        message.metadata["ack_reason"] = event_detail
        message.save(update_fields=["delivered", "to_addr", "metadata"])
    elif event_type == "nack":
        message.metadata["nack_timestamp"] = timestamp
        message.metadata["nack_reason"] = event_detail
        message.save(update_fields=["metadata"])

        decr_message_count(message)

        send_message.delay(str(message.id))
    elif event_type == "delivery_succeeded":
        message.delivered = True
        message.to_addr = ""
        message.metadata["delivery_timestamp"] = timestamp
        message.metadata["delivery_reason"] = event_detail
        message.save(update_fields=["delivered", "metadata", "to_addr"])
    elif event_type == "delivery_failed":
        message.metadata["delivery_failed_reason"] = event_detail
        message.metadata["delivery_failed_timestamp"] = timestamp
        message.save(update_fields=["metadata"])

        decr_message_count(message)

        send_message.delay(str(message.id))
    elif event_type == "read":
        message.delivered = True
        message.to_addr = ""
        message.metadata["read_timestamp"] = timestamp
        message.save(update_fields=["delivered", "to_addr", "metadata"])

    outbound_event_total.labels(event_type, message.channel_id).inc()
    fire_delivery_hook(message)

    return (True, "Event processed")


class EventListener(APIView):

    """
    Triggers updates to outbound messages based on event data from Vumi
    """

    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        """
        Checks for expect event types before continuing
        """
        serializer = EventSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {"accepted": False, "reason": serializer.errors}, status=400
            )

        data = serializer.validated_data

        event_type = {
            "ack": "ack",
            "nack": "nack",
            "delivery_report": "delivery_succeeded",
        }.get(data["event_type"])

        accepted, reason = process_event(
            data["user_message_id"], event_type, data["nack_reason"], data["timestamp"]
        )

        return Response(
            {"accepted": accepted, "reason": reason}, status=200 if accepted else 400
        )

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
        serializer = JunebugEventSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"accepted": False, "reason": serializer.errors}, status=400
            )
        data = serializer.validated_data

        event_type = {
            "submitted": "ack",
            "rejected": "nack",
            "delivery_succeeded": "delivery_succeeded",
            "delivery_failed": "delivery_failed",
        }.get(data["event_type"])

        accepted, reason = process_event(
            data["message_id"], event_type, data["event_details"], data["timestamp"]
        )

        return Response(
            {"accepted": accepted, "reason": reason}, status=200 if accepted else 400
        )


class WassupEventListener(APIView):
    """
    Triggers updates to outbound messages based on event data from Wassup
    """

    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = WassupEventSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"accepted": False, "reason": serializer.errors}, status=400
            )
        data = serializer.validated_data

        dispatcher = {"message.direct_outbound.status": self.handle_status}
        handler = dispatcher.get(data["hook"]["event"])
        return handler(data["hook"], data["data"])

    def handle_status(self, hook, data):
        event_type = {
            "sent": "ack",
            "unsent": "nack",
            "delivered": "delivery_succeeded",
            "failed": "delivery_failed",
        }.get(data["status"])

        accepted, reason = process_event(
            data["message_uuid"],
            event_type,
            data.get("description"),
            data.get("timestamp"),
        )
        return Response(
            {"accepted": accepted, "reason": reason}, status=200 if accepted else 400
        )


class WhatsAppEventListener(APIView):
    permission_classes = (AllowAny,)

    def validate_signature(self, channel, request):
        secret = channel.configuration.get("HMAC_SECRET")
        if not secret:
            raise AuthenticationFailed(
                "No HMAC_SECRET set on channel {}".format(channel.channel_id)
            )

        signature = request.META.get("HTTP_X_ENGAGE_HOOK_SIGNATURE")
        if not signature:
            raise AuthenticationFailed("X-Engage-Hook-Signature header required")

        h = hmac.new(secret.encode(), request.body, sha256)
        if not hmac.compare_digest(base64.b64encode(h.digest()).decode(), signature):
            raise AuthenticationFailed("Invalid hook signature")

    def handle_event(self, serializer):
        data = serializer.validated_data

        event_type = {
            "sent": "ack",
            "delivered": "delivery_succeeded",
            "failed": "delivery_failed",
            "read": "read",
        }.get(data["status"])

        accepted, reason = process_event(data["id"], event_type, "", data["timestamp"])
        return {"accepted": accepted, "reason": reason, "id": data["id"]}

    def handle_inbound(self, serializer):
        serializer.save()
        return {"accepted": True, "id": serializer.data["id"]}

    def post(self, request, channel_id, *args, **kwargs):
        channel = get_object_or_404(Channel, pk=channel_id)
        self.validate_signature(channel, request)

        serializer = WhatsAppWebhookSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"accepted": False, "reason": serializer.errors}, status=400
            )

        events = []
        for event in serializer.validated_data.get("statuses", []):
            event_serializer = WhatsAppEventSerializer(data=event)
            if not event_serializer.is_valid():
                events.append(
                    {
                        "accepted": False,
                        "reason": event_serializer.errors,
                        "id": event.get("id"),
                    }
                )
                continue
            events.append(self.handle_event(event_serializer))

        inbounds = []
        for inbound in serializer.validated_data.get("messages", []):
            preprocess_inbound(inbound, channel)
            inbound_serializer = WhatsAppInboundSerializer(data=inbound)
            if not inbound_serializer.is_valid():
                inbounds.append(
                    {
                        "accepted": False,
                        "reason": inbound_serializer.errors,
                        "id": inbound.get("id"),
                    }
                )
                continue
            inbounds.append(self.handle_inbound(inbound_serializer))

        accepted = all(e["accepted"] for e in events) and all(
            i["accepted"] for i in inbounds
        )
        return Response(
            {"accepted": accepted, "messages": inbounds, "statuses": events},
            status=200 if accepted else 400,
        )


class MetricsView(APIView):

    """ Metrics Interaction
        GET - returns list of all available metrics on the service
        POST - starts up the task that fires all the scheduled metrics
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        status = 200
        resp = {"metrics_available": get_available_metrics()}
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
                    "djangorestframework": rest_framework.__version__,
                },
            },
        }
        return Response(resp, status=status)


class FailedTaskViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    permission_classes = (IsAuthenticated,)
    queryset = OutboundSendFailure.objects.all()
    serializer_class = OutboundSendFailureSerializer
    pagination_class = IdCursorPagination

    def create(self, request):
        status = 201
        resp = {"requeued_failed_tasks": True}
        requeue_failed_tasks.delay()
        return Response(resp, status=status)


class AggregateOutboundViewSet(viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = AggregateOutbounds.objects.all()
    serializer_class = AggregateOutboundSerializer

    def create(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        start = serializer.validated_data.get("start", None)
        end = serializer.validated_data.get("end", None)
        if not end:
            end = datetime.now().date()
        if not start:
            diff = timedelta(days=settings.AGGREGATE_OUTBOUND_BACKTRACK)
            start = (datetime.now() - diff).date()
        aggregate_outbounds.delay(start.isoformat(), end.isoformat())
        return Response({"aggregate_outbounds": True}, status=202)


class ArchivedOutboundViewSet(viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = ArchivedOutbounds.objects.all()
    serializer_class = ArchivedOutboundSerializer

    def create(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        start = serializer.validated_data["start"]
        end = serializer.validated_data["end"]
        archive_outbound.delay(start.isoformat(), end.isoformat())
        return Response({"archived_outbounds": True}, status=202)
