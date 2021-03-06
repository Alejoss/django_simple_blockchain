# Generated by Django 2.2.7 on 2019-11-12 22:51

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Transaction',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('from_address', models.CharField(blank=True, max_length=150)),
                ('to_address', models.CharField(blank=True, max_length=150)),
                ('value', models.PositiveIntegerField(blank=True, null=True)),
                ('fee', models.PositiveIntegerField(blank=True, null=True)),
                ('date_created', models.DateTimeField(null=True)),
                ('data', models.CharField(blank=True, max_length=500)),
                ('sender_public_key', models.CharField(blank=True, max_length=150)),
                ('transaction_data_hash', models.CharField(blank=True, max_length=150)),
                ('sender_signature', models.CharField(blank=True, max_length=150)),
                ('mined_in_block_index', models.PositiveSmallIntegerField(null=True)),
                ('transfer_successful', models.BooleanField(default=False)),
            ],
        ),
    ]
