# Generated by Django 2.1.1 on 2018-09-14 14:26

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('message_sender', '0021_auto_20180504_1446'),
    ]

    operations = [
        migrations.AlterField(
            model_name='aggregateoutbounds',
            name='attempts',
            field=models.IntegerField(help_text='The total number of attempts'),
        ),
        migrations.AlterField(
            model_name='aggregateoutbounds',
            name='channel',
            field=models.ForeignKey(help_text='Which channel this is for', null=True, on_delete=django.db.models.deletion.SET_NULL, to='message_sender.Channel'),
        ),
        migrations.AlterField(
            model_name='aggregateoutbounds',
            name='date',
            field=models.DateField(help_text='The date that the aggregate is for'),
        ),
        migrations.AlterField(
            model_name='aggregateoutbounds',
            name='delivered',
            field=models.BooleanField(help_text='Whether this is for delivery passed or failed messages'),
        ),
        migrations.AlterField(
            model_name='aggregateoutbounds',
            name='total',
            field=models.IntegerField(help_text='The total number of messages'),
        ),
        migrations.AlterField(
            model_name='archivedoutbounds',
            name='archive',
            field=models.FileField(help_text='The file for the archive', upload_to=''),
        ),
        migrations.AlterField(
            model_name='archivedoutbounds',
            name='date',
            field=models.DateField(help_text='The date that the archive is for', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='channel',
            name='channel_type',
            field=models.CharField(choices=[('junebug', 'Junebug'), ('vumi', 'Vumi'), ('http_api', 'HTTP API'), ('wassup', 'Wassup API')], default='junebug', max_length=20),
        ),
        migrations.AlterField(
            model_name='inbound',
            name='created_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='inbounds_created', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='inbound',
            name='updated_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='inbounds_updated', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='outbound',
            name='call_answered',
            field=models.NullBooleanField(default=None, help_text='True if the call has been answered. Not used for text messages'),
        ),
        migrations.AlterField(
            model_name='outbound',
            name='channel',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='message_sender.Channel'),
        ),
        migrations.AlterField(
            model_name='outbound',
            name='created_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='outbounds_created', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='outbound',
            name='resend',
            field=models.NullBooleanField(default=None, help_text='True if this is a resend requested by the user.'),
        ),
        migrations.AlterField(
            model_name='outbound',
            name='updated_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='outbounds_updated', to=settings.AUTH_USER_MODEL),
        ),
    ]
