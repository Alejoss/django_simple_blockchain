from django.shortcuts import render
import base64
import json
import eth_keys, binascii
import hashlib
from merkletools import MerkleTools
from datetime import datetime

from transactions.models import Transaction
from blocks.models import Block
from node.models import Node


def add_transaction(request):
    # Adds a transaction to the memepool
    transaction = json.loads(request.POST.get('transaction_json'))
    public_key_string = transaction['public_key']
    transaction_hash = transaction['transaction_hash']
    signature_raw = transaction['sender_signature']
    print("signature_raw:")
    print(signature_raw)
    signature = eth_keys.keys.Signature(vrs=signature_raw)
    new_bytes = base64.b64decode('"' + public_key_string + '"')
    public_key = eth_keys.keys.PublicKey.from_compressed_bytes(new_bytes)

    transaction_valid = signature.verify_msg(bytes(transaction_hash.encode('utf-8')), public_key)

    if transaction_valid:
        Transaction.objects.create(
            from_address=transaction['from_address'],
            to_address=transaction['to_address'],
            value=transaction['value'],
            fee=transaction['fee'],
            date_created=transaction['date_created'],
            data=transaction['data'],  # TODO this is always blank for now
            sender_public_key=transaction['sender_public_key'],
            transaction_data_hash=transaction['transaction_data_hash'],
            sender_signature=transaction['sender_signature'],
            mined_in_block_index=None,
            transfer_successful=False  # Unconfirmed
        )
        return True
    else:
        return False


def generate_block_header(request, node_id):
    # Get unconfirmed transactions
    transaction_list = Transaction.objects.filter(transfer_successful=False)
    last_mined_block = Block.objects.latest()

    # This node
    this_node = Node.objects.get(node_id=node_id)

    merkle_tree = MerkleTools()
    for transaction in transaction_list:
        merkle_tree.add_leaf(transaction.transaction_data_hash)

    merkle_tree.make_tree()
    merkle_root = None
    if merkle_tree.is_ready:
        merkle_tree.get_merkle_root()
    else:
        return False

    block_data_hash = hashlib.sha256(("1" + str(merkle_root) + str(last_mined_block.difficulty) +
                                      last_mined_block.block_hash +
                                      this_node.miner_address))

    pre_block_header = {
        'index': 1,  # Hardcoded
        'hash_merkle_root': merkle_root,
        'bits': this_node.difficulty,
        'hash_prev_block': last_mined_block.block_hash,
        'mined_by': this_node.miner_address,
        'block_data_hash': block_data_hash,
        'nonce': 0,
        'time': datetime.today().isoformat(),
    }

    return pre_block_header

