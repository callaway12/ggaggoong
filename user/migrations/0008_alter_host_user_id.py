# Generated by Django 3.2.8 on 2021-11-08 04:37

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0007_alter_host_crime_bool'),
    ]

    operations = [
        migrations.AlterField(
            model_name='host',
            name='user_id',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
