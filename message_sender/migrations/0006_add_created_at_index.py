# -*- coding: utf-8 -*-
# Generated by Django 1.9.12 on 2017-01-19 12:05
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message_sender', '0005_outbound_call_answered'),
    ]

    operations = [
        migrations.AlterField(
            model_name='outbound',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, db_index=True),
        ),
    ]