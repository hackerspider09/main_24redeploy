# Generated by Django 4.0.5 on 2023-04-21 13:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0034_alter_team_team_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='transaction_id',
            field=models.CharField(max_length=20, null=True),
        ),
    ]