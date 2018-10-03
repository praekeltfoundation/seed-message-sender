import re

import phonenumbers


def noop(msisdn):
    return msisdn


def vas2nets_voice(msisdn):
    """
    FIXME: this should not need be in this repo

    Vas2Nets is an aggregator in Nigeria, for some reason they need
    MSISDNs prefixed with a 9 instead of the country code to initiate an OBD.
    """
    return re.sub(r"\+?234(\d+)$", r"90\1", msisdn)


def vas2nets_text(msisdn):
    """
    FIXME: this should not need be in this repo

    Vas2Nets is an aggregator in Nigeria, they need MSISDNs in the local
    format, prefixed with a 0, instead of the international format with the
    country code.
    """
    return re.sub(r"\+234(\d+)$", r"234\1", msisdn)


def e_164(msisdn: str) -> str:
    """
    Returns the msisdn in E.164 international format.
    """
    # Phonenumbers library requires the + to identify the country, so we add it if it
    # does not already exist
    number = phonenumbers.parse("+{}".format(msisdn.lstrip("+")), None)
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
