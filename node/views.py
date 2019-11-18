import base64
import json
import eth_keys, binascii
import hashlib
from merkletools import MerkleTools
from datetime import datetime

from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist

from transactions.models import Transaction
from blocks.models import Block, GenesisBlock, BlockCandidate
from node.models import Node
from node.utils import serialize_transactions, compare_proof_zeroes, generate_coinbase_transaction, get_balance_address


def start_node(request):
    # Starts a node with a node id and a miner address
    if request.method == "POST":
        node_id = request.POST.get("node_id")
        Node.objects.create(node_id=node_id)
        return HttpResponse("node %s created" % node_id)
    else:
        return render(request, "start_node.html", {})


def peers(request):
    # shows the node data and the peers
    node = Node.objects.last()
    node_data = {
        'node_id': node.node_id,
        'peers': node.peers
    }
    return HttpResponse(json.dumps(node_data))


def reset_chain(request):
    # Resets the chain to the Genesis block. Erases all the transactions.
    genesis_block, created = GenesisBlock.objects.get_or_create(
        index=0,
        difficulty=0,
        mined_by="000000000000000000000000000",
        nonce=0,
        date_created=datetime.today().isoformat()
    )

    # all_transactions = Transaction.objects.all()
    # for transaction in all_transactions:
    #     transaction.delete()

    genesis_block = {
        'index': genesis_block.index,
        'difficulty': genesis_block.difficulty,
        'mined_by': genesis_block.mined_by,
        'nonce': genesis_block.nonce,
        'date_created': genesis_block.date_created,
    }

    return HttpResponse(json.dumps({'genesis_block': genesis_block}))


def pending_transactions(request):
    # lists the transactions in the memepool
    unconfirmed_transactions = Transaction.objects.filter(transfer_successful=False)
    json_transactions = serialize_transactions(unconfirmed_transactions)

    return HttpResponse(json_transactions)


def confirmed_transactions(request):
    transaction_list = []
    for block in Block.objects.all():
        transaction_list.append(block.transactions)

    print("transaction_list:", transaction_list)
    return HttpResponse(transaction_list)


def add_transaction_mempool(request):
    # Adds a transaction to the mempool
    print("add_transaction_mempool")
    print(request.POST)
    transaction = json.loads(request.POST.get('transaction_json'))
    public_key_string = transaction['public_key']
    transaction_hash = transaction['transaction_data_hash']
    signature_raw = transaction['sender_signature']
    print("signature_raw:")
    print(signature_raw)
    signature = eth_keys.keys.Signature(vrs=signature_raw)
    new_bytes = base64.b64decode('"' + public_key_string + '"')
    public_key = eth_keys.keys.PublicKey.from_compressed_bytes(new_bytes)

    # Verify Signature
    transaction_valid = signature.verify_msg(bytes(transaction_hash.encode('utf-8')), public_key)
    if not transaction_valid:
        return HttpResponse("Invalid signature")

    # Verify Balance
    balance = get_balance_address(transaction["from_address"])
    if balance < int(transaction["value"]):
        return HttpResponse("Not enough funds")

    if transaction_valid:
        Transaction.objects.create(
            from_address=transaction['from_address'],
            to_address=transaction['to_address'],
            value=transaction['value'],
            fee=transaction['fee'],
            date_created=transaction['date_created'],
            data=transaction['data'],  # TODO this is always blank for now
            sender_public_key=transaction['public_key'],
            transaction_data_hash=transaction['transaction_data_hash'],
            sender_signature=transaction['sender_signature'],
            mined_in_block_index=None,
            transfer_successful=False  # Unconfirmed
        )
        return HttpResponse("Transaction added to the Memepool")
    else:
        return HttpResponse("Transaction not added to the Memepool, watch logs")


def generate_block_candidate(request, miner_address):
    # Get unconfirmed transactions
    transaction_list = Transaction.objects.filter(transfer_successful=False)
    last_mined_block = Block.objects.last()
    if not last_mined_block:
        last_mined_block = GenesisBlock.objects.last()

    # add Coinbase transaction
    coinbase_transaction = generate_coinbase_transaction(miner_address, last_mined_block.index + 1)
    # TODO It is generating double coinbase transactions

    merkle_tree = MerkleTools()
    for transaction in transaction_list:
        merkle_tree.add_leaf(transaction.transaction_data_hash)
    merkle_tree.add_leaf(coinbase_transaction['transaction_data_hash'])

    merkle_tree.make_tree()
    merkle_root = ""
    if merkle_tree.is_ready:
        merkle_root = merkle_tree.get_merkle_root()
    else:
        return False

    block_data_hash = hashlib.sha256(("1" + str(merkle_root) + str(last_mined_block.difficulty) +
                                      last_mined_block.block_hash +
                                      miner_address).encode('utf-8'))

    pre_block_header = {
        'index': str(last_mined_block.index + 1),
        'hash_merkle_root': merkle_root,
        'difficulty': settings.DIFFICULTY,  # HARDCODED
        'hash_prev_block': last_mined_block.block_hash,
        'mined_by': miner_address,
        'block_data_hash': block_data_hash.hexdigest(),
        'nonce': 0,
        'time': datetime.today().isoformat(),
    }

    BlockCandidate.objects.create(
        index=last_mined_block.index + 1,  # if mined successfully, this will be the index
        block_data_hash=block_data_hash.hexdigest(),  # Merkle root included here
        prev_block_hash=last_mined_block.block_hash,
        difficulty=last_mined_block.difficulty,
        transactions=serialize_transactions(transaction_list, coinbase_transaction)
    )

    return HttpResponse(json.dumps(pre_block_header))


@csrf_exempt
def add_block(request):
    # Get block candidate with corresponding data hash
    block_data_hash = request.POST.get('block_data_hash')
    nonce = request.POST.get('nonce')
    date_created = request.POST.get('date_created')
    mined_by = request.POST.get('mined_by')

    block_candidate = BlockCandidate.objects.get(block_data_hash=block_data_hash)

    # Verify the Hash / Difficulty
    true_proof = compare_proof_zeroes(block_data_hash, block_candidate.difficulty)
    if not true_proof:
        return HttpResponse("proof provided not valid")

    # Check if the block was not mined by others
    last_block = Block.objects.last()
    if not last_block:
        last_block = GenesisBlock.objects.last()

    candidate_block_index = block_candidate.index

    print("last_block.index", last_block.index)
    print("candidate_block_index", candidate_block_index)
    if last_block.index >= candidate_block_index:
        return HttpResponse("this block was already mined :(")

    # mark transactions as mined
    block_candidate.mark_transactions_as_mined()

    # get block hash
    print("block_data_hash", block_data_hash)
    print("nonce", nonce)
    print("date_created", date_created)
    block_hash = hashlib.sha256((block_data_hash + nonce + date_created).encode('utf-8'))

    Block.objects.create(
        index=block_candidate.index,
        block_data_hash=block_data_hash,
        block_hash=block_hash,
        prev_block_hash=block_candidate.prev_block_hash,
        difficulty=block_candidate.difficulty,
        transactions=block_candidate.transactions,
        mined_by=mined_by,
        nonce=nonce,
        date_created=date_created
    )

    # Remove the transactions from the memepool
    for transaction in json.loads(block_candidate.transactions):
        print("transaction", transaction)
        transaction_mempool = Transaction.objects.get(transaction_data_hash=transaction['transaction_data_hash'])
        transaction_mempool.transfer_successful = True
        transaction_mempool.mined_in_block_index = block_candidate.index
        transaction_mempool.save()

    print("BLOCK ACCEPTED!")
    return HttpResponse("Block accepted, reward paid: %s" % 10)


def address_balance(request, address):
    balance = get_balance_address(address)
    return HttpResponse(balance)


def transaction_detail(request, tran_hash):
    transaction = None
    for block in Block.objects.all():
        transaction = block.get_transaction(tran_hash)

    if transaction:
        return HttpResponse(transaction)
    else:
        return HttpResponse("No transaction found")


def blocks_detail(request):

    block_list = []
    for block in Block.objects.all():
        block_list.append({
            'index': block.index,
            'block_hash': block.block_hash,
            'block_data_hash': block.block_data_hash,
            'prev_block_hash': block.prev_block_hash,
            'difficulty': block.difficulty,
            'transactions': block.transactions,
            'mined_by': block.mined_by,
            'nonce': block.nonce,
            'date_created': block.date_created.isoformat()
        })
    return HttpResponse(json.dumps(block_list))


def block_index(request, index):
    try:
        block = Block.objects.get(index=index)
    except ObjectDoesNotExist:
        return HttpResponse("Block with that index not found")

    block_data = {
        'index': block.index,
        'block_hash': block.block_hash,
        'block_data_hash': block.block_data_hash,
        'prev_block_hash': block.prev_block_hash,
        'difficulty': block.difficulty,
        'transactions': block.transactions,
        'mined_by': block.mined_by,
        'nonce': block.nonce,
        'date_created': block.date_created
    }

    return HttpResponse(json.dumps(block_data))
