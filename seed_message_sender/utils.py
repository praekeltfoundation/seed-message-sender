from django.conf import settings
from importlib import import_module


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
