# -*- coding: utf-8 -*-
# Generated by Django 1.11.11 on 2018-03-19 14:46
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("message_sender", "0018_auto_20180316_1305")]

    operations = [
        migrations.CreateModel(
            name="ArchivedOutbounds",
            fields=[
                (
                    "date",
                    models.DateField(
                        help_text=b"The date that the archive is for",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "archive",
                    models.FileField(
                        help_text=b"The file for the archive", upload_to=b""
                    ),
                ),
            ],
            options={
                "verbose_name": "archived outbounds",
                "verbose_name_plural": "archived outbounds",
            },
        ),
        migrations.AlterModelOptions(
            name="aggregateoutbounds",
            options={
                "verbose_name": "aggregate outbounds",
                "verbose_name_plural": "aggregate outbounds",
            },
        ),
    ]
