# Generated by Django 2.2.7 on 2019-11-13 21:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wallet', '0002_auto_20191113_2127'),
    ]

    operations = [
        migrations.AlterField(
            model_name='wallet',
            name='public_key',
            field=models.BinaryField(blank=True, max_length=150),
        ),
    ]