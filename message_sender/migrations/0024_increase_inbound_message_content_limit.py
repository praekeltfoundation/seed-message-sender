# Generated by Django 2.1.2 on 2018-10-30 15:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("message_sender", "0023_auto_20180926_0741")]

    operations = [
        migrations.AlterField(
            model_name="inbound",
            name="content",
            field=models.CharField(blank=True, max_length=4096, null=True),
        )
    ]