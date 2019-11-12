from django.db import models


class Transaction(models.Model):
    # Fields an unconfirmed transaction must have. JSON compatible
    from_address = models.CharField(blank=True, max_length=150)  # 40 hex digits
    to_address = models.CharField(blank=True, max_length=150)  # 40 hex digits
    value = models.PositiveIntegerField(null=True, blank=True)
    fee = models.PositiveIntegerField(null=True, blank=True)
    date_created = models.DateTimeField(null=True)
    data = models.CharField(blank=True, max_length=500)
    sender_public_key = models.CharField(blank=True, max_length=150)  # 65 hex digits
    transaction_data_hash = models.CharField(blank=True, max_length=150)
    sender_signature = models.CharField(blank=True, max_length=150)
    mined_in_block_index = models.PositiveSmallIntegerField(null=True)
    transfer_successful = models.BooleanField(default=False)
