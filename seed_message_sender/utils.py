import requests
from django.conf import settings
from importlib import import_module
from requests.adapters import HTTPAdapter


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
    url = "%s/%s/%s/addresses/msisdn" % (settings.IDENTITY_STORE_URL,
                                         "identities", identity_uuid)
    params = {"default": True}
    if use_communicate_through:
        params['use_communicate_through'] = True
    headers = {
        'Authorization': 'Token %s' % settings.IDENTITY_STORE_TOKEN,
        'Content-Type': 'application/json'
    }
    session = requests.Session()
    session.mount(settings.IDENTITY_STORE_URL, HTTPAdapter(max_retries=5))
    result = session.get(
        url,
        params=params,
        headers=headers,
        timeout=settings.DEFAULT_REQUEST_TIMEOUT
    )
    result.raise_for_status()
    r = result.json()
    if len(r["results"]) > 0:
        return r["results"][0]["address"]
    else:
        return None


def get_identity_by_address(address_value, address_type="msisdn"):
    url = "%s/identities/search/" % (settings.IDENTITY_STORE_URL)

    params = {"details__addresses__%s" % address_type: address_value}
    headers = {
        'Authorization': 'Token %s' % settings.IDENTITY_STORE_TOKEN,
        'Content-Type': 'application/json'
    }

    session = requests.Session()
    session.mount(settings.IDENTITY_STORE_URL, HTTPAdapter(max_retries=5))
    result = session.get(
        url,
        params=params,
        headers=headers,
        timeout=settings.DEFAULT_REQUEST_TIMEOUT
    )
    result.raise_for_status()
    r = result.json()
    if len(r["results"]) > 0:
        return r
    else:
        return None


def create_identity(identity):
    url = "%s/identities/" % (settings.IDENTITY_STORE_URL)
    headers = {
        'Authorization': 'Token %s' % settings.IDENTITY_STORE_TOKEN,
        'Content-Type': 'application/json'
    }

    session = requests.Session()
    session.mount(settings.IDENTITY_STORE_URL, HTTPAdapter(max_retries=5))
    result = session.post(
        url,
        json=identity,
        headers=headers,
        timeout=settings.DEFAULT_REQUEST_TIMEOUT
    )
    result.raise_for_status()
    r = result.json()
    return r
