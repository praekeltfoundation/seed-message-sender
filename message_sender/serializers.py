from .models import Inbound, Outbound, OutboundSendFailure, Channel
from rest_hooks.models import Hook
from rest_framework import serializers
from seed_services_client.identity_store import IdentityStoreApiClient

from django.conf import settings

is_client = IdentityStoreApiClient(
    api_url=settings.IDENTITY_STORE_URL,
    auth_token=settings.IDENTITY_STORE_TOKEN
)


class OneFieldRequiredValidator:
    def __init__(self, fields):
        self.fields = fields

    def set_context(self, serializer):
        self.is_create = getattr(serializer, 'instance', None) is None

    def __call__(self, data):
        if self.is_create:

            valid = False
            for field in self.fields:
                if data.get(field):
                    valid = True

            if not valid:
                raise serializers.ValidationError(
                    "to_addr or to_identity must be populated")


class OutboundSerializer(serializers.HyperlinkedModelSerializer):

    channel = serializers.PrimaryKeyRelatedField(
        queryset=Channel.objects.all(), required=False)

    class Meta:
        model = Outbound
        fields = (
            'url', 'id', 'version', 'to_addr', 'vumi_message_id', 'content',
            'delivered', 'attempts', 'metadata', 'created_at', 'updated_at',
            'channel', 'to_identity')
        validators = [OneFieldRequiredValidator(['to_addr', 'to_identity'])]


class InboundSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Inbound
        fields = (
            'url', 'id', 'message_id', 'in_reply_to', 'to_addr',
            'from_addr', 'content', 'transport_name', 'transport_type',
            'helper_metadata', 'created_at', 'updated_at', 'from_identity')

    def to_internal_value(self, data):
        """
        Adds extra data to the helper_metadata field.
        """
        if "session_event" in data:
            data['helper_metadata']['session_event'] = data['session_event']

        if "from_addr" in data:
            result = is_client.get_identity_by_address("msisdn",
                                                       data['from_addr'])

            if 'results' in result and result['results']:
                data['from_identity'] = result['results'][0]['id']
            else:
                identity = is_client.create_identity(data['from_addr'])
                data['from_identity'] = identity['id']

            del data['from_addr']

        return super(InboundSerializer, self).to_internal_value(data)


class JunebugInboundSerializer(serializers.HyperlinkedModelSerializer):
    """
    Maps fields from Junebug onto fields expected by the Inbound model.
    """
    reply_to = serializers.CharField(source='in_reply_to')
    to = serializers.CharField(source='to_addr')
    channel_id = serializers.CharField(source='transport_name')
    channel_data = serializers.JSONField(source='helper_metadata')

    class Meta:
        model = Inbound
        fields = (
            'url', 'id', 'message_id', 'reply_to', 'to', 'from_addr',
            'content', 'channel_id', 'channel_data', 'created_at',
            'updated_at', 'from_identity')

    def to_internal_value(self, data):
        """
        Maps Junebug 'from' field to 'from_addr' expected by serializer since
        'from' is a python keyword.
        """
        if "from" not in data:
            raise serializers.ValidationError({
                'from': 'This field is required.'
            })
        else:
            result = is_client.get_identity_by_address("msisdn", data['from'])

            if 'results' in result and result['results']:
                data['from_identity'] = result['results'][0]['id']
            else:
                identity = is_client.create_identity(data['from'])
                data['from_identity'] = identity['id']

            del data['from']

        return super(JunebugInboundSerializer, self).to_internal_value(data)


class HookSerializer(serializers.ModelSerializer):

    class Meta:
        model = Hook
        read_only_fields = ('user',)


class CreateUserSerializer(serializers.Serializer):
    email = serializers.EmailField()


class OutboundSendFailureSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = OutboundSendFailure
        fields = ('url', 'id', 'outbound', 'task_id', 'initiated_at', 'reason')
