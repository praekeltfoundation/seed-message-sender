from django.conf import settings
from importlib import import_module
from seed_services_client import IdentityStoreApiClient
from datetime import timedelta
from django.utils import timezone
from django.utils.dateparse import parse_datetime

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
    module_name, func_name = dotted_path_to_callable.rsplit(".", 1)
    mod = import_module(module_name)
    func = getattr(mod, func_name)
    return func


def get_identity_address(identity_uuid, use_communicate_through=False):
    params = {"default": True}
    if use_communicate_through:
        params["use_communicate_through"] = True

    return identity_store_client.get_identity_address(identity_uuid, params=params)


def get_identity_by_address(address_value, address_type="msisdn"):
    r = identity_store_client.get_identity_by_address(address_type, address_value)

    results = list(r["results"])
    if len(results) > 0:
        return results
    else:
        return None


def create_identity(identity):
    return identity_store_client.create_identity(identity)


def is_in_time_interval(interval, timestamp=None):
    """
    Checks whether a timestamp falls within an interval or not, and when would be the
    next time that it would fall within the interval.

    interval (str): The interval to check, given by two ISO-8601 times,
        `<time1>/<time2>`, eg. "09:00:00Z/17:00:00Z"
    timestamp (datetime, optional): The timestamp to check. Defaults to the current time.

    Returns (in_interval (bool), safe (datetime))
    """
    if timestamp is None:
        timestamp = timezone.now()

    start, end = interval.split("/")
    start = parse_datetime(f"{timestamp.date().isoformat()}T{start}")
    end = parse_datetime(f"{timestamp.date().isoformat()}T{end}")

    in_interval = start < timestamp < end
    if in_interval:
        return in_interval, timestamp
    else:
        if timestamp > end:
            return in_interval, start + timedelta(days=1)
        else:
            return in_interval, start
