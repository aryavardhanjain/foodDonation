# Generated by Django 5.0 on 2024-05-08 00:37

import django.db.models.deletion
from django.db import migrations, models
from django.db.migrations import RunPython


def set_default_organization(apps, schema_editor):
    Organization = apps.get_model('organization', 'Organization')
    default_org = Organization.objects.first()  # Make sure this does not return None!
    if default_org is not None:
        Rating = apps.get_model('accounts', 'Rating')
        for rating in Rating.objects.all():
            rating.organization_id = default_org.pk
            rating.save()

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_fooddonation_scheduled_date_and_more'),
        ('organization', '0003_alter_event_date_alter_event_time'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='rating',
            name='content_type',
        ),
        migrations.RemoveField(
            model_name='rating',
            name='object_id',
        ),
        migrations.AddField(
            model_name='rating',
            name='organization',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='ratings', to='organization.organization'),
            preserve_default=False,
        ),
        RunPython(set_default_organization)
    ]
