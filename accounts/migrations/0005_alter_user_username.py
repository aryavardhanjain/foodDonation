# Generated by Django 5.0 on 2024-05-04 14:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_remove_user_phone_number_remove_userprofile_latitude_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=50, null=True, unique=True),
        ),
    ]
