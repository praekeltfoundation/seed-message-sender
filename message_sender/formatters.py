import re


def noop(msisdn):
    return msisdn


def vas2nets_voice(msisdn):
    """
    FIXME: this should not need be in this repo

    Vas2Nets is an aggregator in Nigeria, for some reason they need
    MSISDNs prefixed with a 9 instead of the country code to initiate an OBD.
    """
    return re.sub(r'\+?234(\d+)$', r'90\1', msisdn)


def vas2nets_text(msisdn):
    """
    FIXME: this should not need be in this repo

    Vas2Nets is an aggregator in Nigeria, they need MSISDNs in the local
    format, prefixed with a 0, instead of the international format with the
    country code.
    """
    return re.sub(r'\+234(\d+)$', r'234\1', msisdn)
