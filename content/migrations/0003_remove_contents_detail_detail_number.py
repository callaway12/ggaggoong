# Generated by Django 3.2.8 on 2021-10-31 04:56

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('content', '0002_contents_detail_detail_number'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='contents_detail',
            name='detail_number',
        ),
    ]
