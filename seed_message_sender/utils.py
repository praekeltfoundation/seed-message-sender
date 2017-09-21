from django.conf import settings
from importlib import import_module
from seed_services_client import IdentityStoreApiClient

identity_store_client = IdentityStoreApiClient(
    settings.IDENTITY_STORE_TOKEN,
    settings.IDENTITY_STORE_URL,
    retries=5,
    timeout=settings.DEFAULT_REQUEST_TIMEOUT,
)


def get_available_metrics():
    available_metrics = []
    available_metrics.extend(settings.METRICS_REALTIME)
    available_metrics.extend(settings.METRICS_SCHEDULED)

    return available_metrics


def load_callable(dotted_path_to_callable):
    module_name, func_name = dotted_path_to_callable.rsplit('.', 1)
    mod = import_module(module_name)
    func = getattr(mod, func_name)
    return func


def get_identity_address(identity_uuid, use_communicate_through=False):
    params = {"default": True}
    if use_communicate_through:
        params['use_communicate_through'] = True

    return identity_store_client.get_identity_address(
        identity_uuid, params=params)


def get_identity_by_address(address_value, address_type="msisdn"):
    r = identity_store_client.get_identity_by_address(address_type,
                                                      address_value)

    results = list(r["results"])
    if len(results) > 0:
        return results
    else:
        return None


def create_identity(identity):
    return identity_store_client.create_identity(identity)
