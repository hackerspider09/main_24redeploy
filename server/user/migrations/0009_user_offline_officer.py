# Generated by Django 4.0.5 on 2023-03-05 10:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0008_alter_referral_referral_code'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='offline_officer',
            field=models.BooleanField(default=False),
        ),
    ]
