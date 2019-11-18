import base64
import json
import eth_keys, binascii
import hashlib
from merkletools import MerkleTools
from datetime import datetime

from django.db import models


class Wallet(models.Model):
    address = models.CharField(max_length=150, blank=True)
    private_key = models.BinaryField(max_length=150, blank=True)
    public_key = models.BinaryField(max_length=150, blank=True)
    default_fee = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return self.address

    def generate_keys(self, passphrase):
        private_key = eth_keys.keys.PrivateKey(
            binascii.unhexlify((hashlib.sha256(bytes(passphrase))).hexdigest()))
        public_key = private_key.public_key
        pubkey_compressed = str(public_key)[2:66] + str(int(public_key) % 2)
        h = hashlib.new('ripemd160')
        h.update(pubkey_compressed.encode('utf-8'))
        address = h.hexdigest()

        self.address = address
        self.private_key = private_key.to_bytes()
        self.public_key = public_key.to_bytes()
        self.save()

    def generate_transaction(self, destination_address, value):

        from_address = self.address
        to_address = destination_address
        value = value
        fee = 1  # Hardcoded
        date_created = str(datetime.utcnow().isoformat())
        data = ""

        # Get the public key in the correct format
        public_key_obj = eth_keys.keys.PublicKey(self.public_key)
        public_key_bytes = public_key_obj.to_compressed_bytes()
        encoded_bytes = base64.b64encode(public_key_bytes)
        public_key_string = str(encoded_bytes)[1:].strip("'")

        transaction_data_json = json.dumps({'from_address': from_address, 'to_address': to_address, 'value': value,
                                            'fee': fee, 'date_created': date_created,
                                            'data': data, 'public_key': public_key_string})

        transaction_data_hash = hashlib.sha256(transaction_data_json.encode('utf-8'))  # For the Header

        # Sign the transaction hash with the sender private key
        sender_private_key = eth_keys.keys.PrivateKey(self.private_key)
        signature = sender_private_key.sign_msg(bytes(transaction_data_hash.hexdigest().encode('utf-8')))
        print("signature: %s" % signature)

        transaction_json = json.dumps({
            'from_address': from_address,
            'to_address': to_address,
            'value': value,
            'fee': fee,
            'date_created': date_created,
            'data': data,
            'public_key': public_key_string,
            'transaction_data_hash': transaction_data_hash.hexdigest(),
            'sender_signature': [signature.v, signature.r, signature.s],
            'mined_in_block_index': None,
            'transfer_successful': False
        })

        return transaction_json
