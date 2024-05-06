# Generated by Django 5.0 on 2024-05-05 10:06

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('organization', '0007_remove_organization_phone_number'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='event',
            name='content_type',
        ),
        migrations.RemoveField(
            model_name='event',
            name='object_id',
        ),
        migrations.AddField(
            model_name='event',
            name='organization',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, related_name='events', to='organization.organization'),
        ),
    ]
