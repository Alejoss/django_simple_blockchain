import json
import hashlib
from django.db import models


class GenesisBlock(models.Model):
    # A Singleton
    def save(self, *args, **kwargs):
        self.pk = 1
        block_data_hash = hashlib.sha256((str(self.index) + str(self.difficulty)).encode('utf-8'))
        block_hash = hashlib.sha256((block_data_hash.hexdigest() + str(self.nonce) + self.date_created).encode('utf-8'))

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

    def get_transactions_address(self, address):
        transactions_address = []
        for transaction in json.loads(self.transactions):
            if transaction['from_address'] == address or transaction['to_address'] == address:
                transactions_address.append(transaction)
        return transactions_address

    def get_transaction(self, transaction_hash):
        for transaction in json.loads(self.transactions):
            if transaction['transaction_data_hash'] == transaction_hash:
                return transaction


class BlockCandidate(models.Model):
    index = models.IntegerField(default=0, null=True)
    block_data_hash = models.CharField(blank=True, max_length=150)  # Merkle root included here
    prev_block_hash = models.CharField(blank=True, max_length=150)
    difficulty = models.SmallIntegerField(null=True)
    transactions = models.CharField(blank=True, max_length=10000)

    def mark_transactions_as_mined(self):
        transaction_list = json.loads(self.transactions)
        for transaction in transaction_list:
            transaction['transfer_successful'] = True,
            transaction['mined_in_block_index'] = self.index
        self.transactions = json.dumps(transaction_list)
