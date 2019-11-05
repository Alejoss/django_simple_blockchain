from django.db import models
from django.contrib.postgres.fields import JSONField


class Transaction(models.Model):
    # Fields an unconfirmed transaction must have. JSON compatible
    from_address = models.CharField(blank=True, max_length=150)  # 40 hex digits
    to_address = models.CharField(blank=True, max_length=150)  # 40 hex digits
    value = models.PositiveIntegerField(null=True, blank=True)
    fee = models.PositiveIntegerField(null=True, blank=True)
    date_created = models.DateTimeField(null=True)
    data = JSONField()
    sender_public_key = models.CharField(blank=True, max_length=150)  # 65 hex digits
    transaction_data_hash = models.CharField(blank=True, max_length=150)  # ? hex digits
    sender_signature = models.CharField(blank=True, max_length=150)  # ? hex digits
    mined_in_block_index = models.PositiveSmallIntegerField(null=True)
    transfer_successful = models.BooleanField(default=False)

