from django.shortcuts import render
import base64
import json
import eth_keys, binascii
import hashlib
from merkletools import MerkleTools
from datetime import datetime

from transactions.models import Transaction
from blocks.models import Block, GenesisBlock
from node.models import Node


def reset_chain(request):
    # Resets the chain to the Genesis block. Erases all the transactions.
    genesis_block, created = GenesisBlock.objects.get_or_create(
        index=0,
        difficulty=0,
        mined_by="000000000000000000000000000",
        nonce=0,
        date_created=datetime.today().isoformat()
    )

    all_transactions = Transaction.objects.all()
    for transaction in all_transactions:
        transaction.delete()

    return


def add_transaction_mempool(request):
    # Adds a transaction to the mempool
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
    if not last_mined_block:
        last_mined_block = GenesisBlock.objects.get(pk=1)

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


def add_new_block(request):
    block_data = request.POST.get('block_data')
    block = Block.objects.craete(
        index=block_data['index'],
        block_data_hash=block_data['block_data_hash'],
        block_hash=block_data['block_hash'],
        prev_block_hash=block_data['prev_block_hash'],
        difficulty=block_data['difficulty'],
        transactions=block_data['transactions'],
        mined_by=block_data['mined_by'],
        nonce=block_data['nonce'],
        date_created=block_data['date_created']
    )

    return block  # TODO revisar API
