# -*- coding: utf-8 -*-
# Generated by Django 1.9.12 on 2017-03-23 10:42
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message_sender', '0007_outboundsendfailure'),
    ]

    operations = [
        migrations.AlterField(
            model_name='inbound',
            name='from_addr',
            field=models.CharField(db_index=True, max_length=255),
        ),
    ]