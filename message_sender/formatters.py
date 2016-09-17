import re


def noop(msisdn):
    return msisdn


def vas2nets_voice(msisdn):
    """
    FIXME: this should not need be in this repo

    Vas2Nets is an aggregator in Nigeria, for some reason they need
    MSISDNs prefixed with a 9 instead of the country code to initiate an OBD.
    """
    return re.sub(r'\+?234(\d+)$', r'9\1', msisdn)
