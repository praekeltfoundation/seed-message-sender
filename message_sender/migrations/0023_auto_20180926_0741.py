# Generated by Django 2.1.1 on 2018-09-26 07:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("message_sender", "0022_auto_20180914_1426")]

    operations = [
        migrations.AlterField(
            model_name="channel",
            name="channel_type",
            field=models.CharField(
                choices=[
                    ("junebug", "Junebug"),
                    ("vumi", "Vumi"),
                    ("http_api", "HTTP API"),
                    ("wassup", "Wassup API"),
                    ("whatsapp", "WhatsApp API"),
                ],
                default="junebug",
                max_length=20,
            ),
        )
    ]
