import hashlib
from django.db import models


class GenesisBlock(models.Model):
    # A Singleton
    def save(self, *args, **kwargs):
        self.pk = 1
        block_data_hash = hashlib.sha256(str(self.index) + str(self.difficulty))
        block_hash = hashlib.sha256(block_data_hash + str(self.nonce) + self.date_created)

        self.block_data_hash = block_data_hash
        self.block_hash = block_hash

        super(GenesisBlock, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass

    index = models.IntegerField(default=0, null=True)
    difficulty = models.SmallIntegerField(default=0)
    mined_by = models.CharField(default="000000000000000000000000000", max_length=150)
    nonce = models.IntegerField(default=0)
    block_data_hash = models.CharField(blank=True, max_length=150)  # Merkle root included here
    date_created = models.DateTimeField(null=True)
    block_hash = models.CharField(blank=True, max_length=150)


class Block(models.Model):
    index = models.IntegerField(null=True)
    block_hash = models.CharField(blank=True, max_length=150)
    block_data_hash = models.CharField(blank=True, max_length=150)  # Merkle root included here
    prev_block_hash = models.CharField(blank=True, max_length=150)
    difficulty = models.SmallIntegerField(null=True)
    transactions = models.CharField(blank=True, max_length=10000)
    mined_by = models.CharField(blank=True, max_length=150)
    nonce = models.IntegerField(null=True)
    date_created = models.DateTimeField(null=True)
