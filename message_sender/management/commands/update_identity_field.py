from django.core.management.base import BaseCommand
from django.core.exceptions import ObjectDoesNotExist
from django.db import connection
import datetime

from message_sender.models import IdentityLookup, Outbound, Inbound

import gc
import pytz


def queryset_iterator_created_at(queryset, chunksize=1000):
    pk = datetime.datetime(2100, 1, 1).replace(tzinfo=pytz.UTC)
    last_pk = queryset.order_by('created_at').values_list(
        'created_at', flat=True).first()
    if last_pk is not None:
        queryset = queryset.order_by('-created_at')
        while pk > last_pk:
            for row in queryset.filter(created_at__lt=pk)[:chunksize]:
                pk = row.created_at
                yield row
            gc.collect()


def queryset_iterator_msisdn(queryset, chunksize=1000):
    pk = ''
    last_pk = queryset.order_by('-msisdn').values_list(
        'msisdn', flat=True).first()
    if last_pk is not None:
        queryset = queryset.order_by('msisdn')
        while pk < last_pk:
            for row in queryset.filter(msisdn__gt=pk)[:chunksize]:
                pk = row.msisdn
                yield row
            gc.collect()


class Command(BaseCommand):
    help = ("This command updates the identity field on the outbound and "
            "inbound table.")

    def add_arguments(self, parser):
        parser.add_argument(
            "--loop", dest="loop", default="ID",
            help=("Loop identities(ID), messages(MSG) or SQL."))

    def handle(self, *args, **options):
        loop = options['loop']

        if loop == "ID":
            self.update_by_id()

        elif loop == "MSG":
            self.update_by_msg()

        elif loop == "SQL":
            self.update_by_sql()

        else:
            self.stdout.write("Invalid Loop(ID, MSG, SQL)")

        self.stdout.write("Updated")

    def update_by_id(self):
        identities = queryset_iterator_msisdn(IdentityLookup.objects.all())

        for identity in identities:

            Outbound.objects.filter(to_addr=identity.msisdn).update(
                to_addr='', to_identity=identity.identity)

            Inbound.objects.filter(from_addr=identity.msisdn).update(
                from_addr='', from_identity=identity.identity)

    def update_by_msg(self):
        outbounds = Outbound.objects.exclude(to_addr='')
        outbounds = queryset_iterator_created_at(outbounds)

        for outbound in outbounds:
            try:
                identity = IdentityLookup.objects.get(
                    msisdn=outbound.to_addr)
                outbound.to_addr = ''
                outbound.to_identity = identity.identity
                outbound.save()
            except ObjectDoesNotExist:
                self.stdout.write("Identity not Found: %s" % outbound.to_addr)

        inbounds = Inbound.objects.exclude(from_addr='')
        inbounds = queryset_iterator_created_at(inbounds)
        for inbound in inbounds:
            try:
                identity = IdentityLookup.objects.get(
                    msisdn=inbound.from_addr)
                inbound.from_addr = ''
                inbound.from_identity = identity.identity
                inbound.save()
            except ObjectDoesNotExist:
                self.stdout.write("Identity not Found: %s" % inbound.to_addr)

    def update_by_sql(self):
        update_out_identity = """
            update message_sender_outbound a
            set to_identity = b.identity
            from
                message_sender_identitylookup b
            where
                a.to_addr = b.msisdn"""

        update_out_addr = """
            update message_sender_outbound
            set to_addr = ''
            where to_identity != '';"""

        update_in_identity = """
            update message_sender_inbound a
            set from_identity = b.identity
            from
                message_sender_identitylookup b
            where
                a.from_addr = b.msisdn"""

        update_in_addr = """
            update message_sender_inbound
            set from_addr = ''
            where from_identity != '';"""

        with connection.cursor() as cursor:
            cursor.execute(update_out_identity)
            cursor.execute(update_out_addr)
            cursor.execute(update_in_identity)
            cursor.execute(update_in_addr)
