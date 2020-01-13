import base64
import json
import eth_keys, binascii
import hashlib
import requests
from merkletools import MerkleTools
from datetime import datetime

from django.shortcuts import render, redirect, reverse
from django.http import HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist

from transactions.models import Transaction
from blocks.models import Block, GenesisBlock, BlockCandidate
from node.models import Node, Peer
from node.utils import serialize_transactions, compare_proof_zeroes, generate_coinbase_transaction, \
    get_balance_address, get_all_addresses, concat_header_nonce

# from blockchain_django.miner import miner_address


def start_node(request):
    # Starts a node with a node id and a miner address
    if request.method == "POST":
        node_id = request.POST.get("node_id")
        Node.objects.create(node_id=node_id)
        return HttpResponse("node %s created" % node_id)
    else:
        return render(request, "start_node.html", {})


def debug(request):
    # Shows all the blockchain information
    data = {
        'self_url': "http://localhost:",
        'peers': {},
        'chain': {
            'blocks': [],
        },
        'pending_transactions': [],
        'current_difficulty': settings.DIFFICULTY,
        'mining_jobs': "asdjkdfgsdfsdg",
        'confirmed_balances': {}
    }

    blocks = Block.objects.all()
    for b in blocks:
        transactions = [t.block_hash for t in b]

        data['chain']['blocks'].append({
            'index': b.index,
            'transactions': transactions,
            'difficulty': b.difficulty,
            'prevBlockHash': b.prev_block_hash,
            'minedBy': b.mined_by,
            'nonce': b.nonce,
            'blockDataHash': b.block_data_hash,
            'dateCreated': b.date_created,
            'blockHash': b.block_hash,

        })

    unconfirmed_transactions = Transaction.objects.filter(transfer_successful=False)
    for t in unconfirmed_transactions:
        data['pending_transactions'].append({
            'from_address': t.from_address,
            'to_address': t.to_address,
            'value': t.value,
            'transaction_data_hash': t.transaction_data_hash
        })

    # confirmed balances
    all_addresses = get_all_addresses()
    for a in all_addresses:
        balance = get_balance_address(a)
        data['confirmed_balances'][a] = balance

    return HttpResponse(json.dumps(data))


def balances(request):
    data = {}
    all_addresses = get_all_addresses()
    for a in all_addresses:
        balance = get_balance_address(a)
        data[a] = balance

    return HttpResponse(json.dumps(data))


def peers(request):
    # shows the node data and the peers
    this_node = Node.objects.get(id=983983983)
    node_peers = Peer.objects.filter(related_node=this_node)
    node_data = {
        'node_id': this_node.node_id,
        'node_peers': [(x.node_id, x.node_url) for x in node_peers]
    }
    return HttpResponse(json.dumps(node_data))


def connect_peer(request):
    # Connects to a peer given a Peer Id and a Peer Url
    if request.method == "POST":
        peer_id = request.POST.get("peer_id")
        node_url = request.POST.get("node_url")
        this_node = Node.objects.get(id=settings.NODE_ID)

        Peer.objects.create(node_id=peer_id, node_url=node_url, related_node=this_node)
        return redirect(reverse('peers'))
    else:
        return render(request, "connect_peer.html", {})


def sync_blockchain_peer(request):
    # Shows the possible peers. User may choose to sync with one that has more blocks
    if request.method == "POST":
        peer_id = request.POST.get("peer_id")
        peer = Peer.objects.get(node_id=peer_id)
        # Get block data from peer
        block_data = requests.get(peer.node_url+"blocks/").json()
        # Get the last block from peer, compare to local last block index
        local_last_block = Block.objects.last()
        peer_last_block = block_data[len(block_data)]
        if peer_last_block['index'] > local_last_block.index:
            # add missing blocks to local chain
            block_diff = peer_last_block['index'] - local_last_block.index
            extra_blocks = block_data[:block_diff]
            counter = 0
            for block in extra_blocks:
                if counter == 0:
                    # make sure the first extra block connects with the local last block hash
                    if local_last_block.block_hash == block["prev_block_hash"]:
                        Block.objects.create(
                            index=peer_last_block['index'],
                            block_data_hash=peer_last_block['block_data_hash'],
                            block_hash=peer_last_block['block_hash'],
                            prev_block_hash=peer_last_block['prev_block_hash'],
                            difficulty=peer_last_block['difficulty'],
                            transactions=peer_last_block['transactions'],
                            mined_by=peer_last_block['mined_by'],
                            nonce=peer_last_block['nonce'],
                            date_created=peer_last_block['date_created']
                        )
                    else:
                        return HttpResponse("Las block hashes do not correspond")
                else:
                    Block.objects.create(
                        index=peer_last_block['index'],
                        block_data_hash=peer_last_block['block_data_hash'],
                        block_hash=peer_last_block['block_hash'],
                        prev_block_hash=peer_last_block['prev_block_hash'],
                        difficulty=peer_last_block['difficulty'],
                        transactions=peer_last_block['transactions'],
                        mined_by=peer_last_block['mined_by'],
                        nonce=peer_last_block['nonce'],
                        date_created=peer_last_block['date_created']
                    )
                    counter += 1

            return HttpResponse("Blockchain Synced")

        else:
            return HttpResponse("Peer doesn't have a longer chain")

    else:
        this_node = Node.objects.get(id=settings.NODE_ID)
        node_peers = Peer.objects.filter(related_node=this_node)
        peer_data = []

        for peer in node_peers:
            # get blocks
            block_data = (requests.get(peer.node_url + "blocks/")).json()
            peer_data.append([peer.node_id, len(block_data)])

        return render(request, "sync_peers.html", {'peer_data': peer_data})


def reset_chain(request):
    # Resets the chain to the Genesis block. Erases all the transactions.
    all_transactions = Transaction.objects.all()
    for transaction in all_transactions:
        transaction.delete()

    genesis_block = GenesisBlock.objects.last()
    if genesis_block:
        genesis_block.index = 0
        genesis_block.difficulty = 0
        genesis_block.mined_by = "000000000000000000000000000"
        genesis_block.nonce = 0
        genesis_block.date_created = datetime.today()
        genesis_block.save()
    else:
        GenesisBlock.objects.create(
            index=0,
            difficulty=0,
            mined_by="000000000000000000000000000",
            nonce=0,
            date_created=datetime.today(),
        )

    Block.objects.all().delete()

    genesis_block = {
        'index': genesis_block.index,
        'difficulty': genesis_block.difficulty,
        'mined_by': genesis_block.mined_by,
        'nonce': genesis_block.nonce,
        'date_created': genesis_block.date_created.isoformat(),
        'block_data_hash': genesis_block.block_data_hash.hexdigest(),
        'block_hash': genesis_block.block_hash.hexdigest()
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
        print("block:%s" % block.id)
        print(block.transactions)
        print("----------------")
        print(json.loads(block.transactions))
        transaction_list.extend(block.transactions)

    return HttpResponse(transaction_list)


def add_transaction_mempool(request):
    # Adds a transaction to the mempool
    transaction = json.loads(request.POST.get('transaction_json'))
    public_key_string = transaction['public_key']
    transaction_hash = transaction['transaction_data_hash']
    signature_raw = transaction['sender_signature']
    signature = eth_keys.keys.Signature(vrs=signature_raw)
    new_bytes = base64.b64decode('"' + public_key_string + '"')
    public_key = eth_keys.keys.PublicKey.from_compressed_bytes(new_bytes)

    # Verify Signature
    transaction_valid = signature.verify_msg(bytes(transaction_hash.encode('utf-8')), public_key)
    if not transaction_valid:
        return HttpResponse("Invalid signature")

    # Verify Balance
    balance = get_balance_address(transaction["from_address"])
    if balance < int(transaction["value"]):  # TODO and fee
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
    transaction_list = Transaction.objects.filter(transfer_successful=False).exclude(
        from_address="0000000000000000000000000000000000000000")
    last_mined_block = Block.objects.last()
    if not last_mined_block:
        last_mined_block = GenesisBlock.objects.last()
    # add Coinbase transaction
    coinbase_transaction = generate_coinbase_transaction(miner_address, last_mined_block.index + 1)

    merkle_tree = MerkleTools()
    for transaction in transaction_list:
        merkle_tree.add_leaf(transaction.transaction_data_hash)
    merkle_tree.add_leaf(coinbase_transaction['transaction_data_hash'])

    merkle_tree.make_tree()
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

    print("--------------------------------------------------------")
    return HttpResponse(json.dumps(pre_block_header))


@csrf_exempt
def add_block(request):
    # Get block candidate with corresponding data hash
    block_data_hash = request.POST.get('block_data_hash')
    nonce = request.POST.get('nonce')
    date_created = request.POST.get('date_created')
    mined_by = request.POST.get('mined_by')

    block_candidate = BlockCandidate.objects.get(block_data_hash=block_data_hash)

    print("block_candidate.transactions:")
    print(block_candidate.transactions)

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

    # Propagate the block
    this_node = Node.objects.get(id=settings.NODE_ID)
    node_peers = Peer.objects.filter(node=this_node)
    block_data = {
        'block_data_hash': block_data_hash,
        'nonce': nonce,
        'date_created': date_created,
        'mined_by': mined_by,
        'transactions': block_candidate.transactions,
        'block_height': block_candidate.index
    }

    for peer in node_peers:
        add_block_url = peer.node_url + "/node/submit_block/"
        try:
            requests.post(url=add_block_url, data=block_data)
        except Exception as e:
            print("There was an error propagating the block to %s" % peer.node_url)
            print(e)

    return HttpResponse("Block accepted")


@csrf_exempt
def add_new_block(request):
    # Receive a block from another node. No block candidate in local DB.
    # Usually accumulated difficulty is calculated and compared. For simplicity, block height is used instead
    if request.method == "POST":
        block_data_hash = request.POST.get('block_data_hash')
        nonce = request.POST.get('nonce')
        date_created = request.POST.get('date_created')
        mined_by = request.POST.get('mined_by')
        transactions = request.POST.get('transactions')
        block_height = request.POST.get('block_height')

        print("POST DATA: ")
        print(request.POST.data)

        # Compare the block height
        last_block = Block.objects.last()
        if not last_block.index == int(block_height):
            # The block height is not correct
            return HttpResponse("Incorrect Block Height")

        # Validate the nonce
        block_hash = concat_header_nonce(block_data_hash, date_created, nonce)
        is_true_nonce = compare_proof_zeroes(block_hash, settings.DIFFICULTY)
        if not is_true_nonce:
            return HttpResponse("NOT A VALID NONCE")

        # Create Block
        Block.objects.create(
            index=block_height,
            block_data_hash=block_data_hash,
            block_hash=block_hash,
            prev_block_hash=last_block.prev_block_hash,
            difficulty=settings.DIFFICULTY,
            transactions=transactions,
            mined_by=mined_by,
            nonce=nonce,
            date_created=date_created
        )

        # Remove the transactions from the memepool
        for transaction in json.loads(transactions):
            print("transaction", transaction)
            try:
                transaction_mempool = Transaction.objects.get(
                    transaction_data_hash=transaction['transaction_data_hash'])
                transaction_mempool.transfer_successful = True
                transaction_mempool.mined_in_block_index = block_height
                transaction_mempool.save()
            except Exception as e:
                print(e)
                print("There was an error removing this transaction from the memepool")

        # Propagate the block
        this_node = Node.objects.get(id=settings.NODE_ID)
        node_peers = Peer.objects.filter(node=this_node)
        for peer in node_peers:
            add_block_url = peer.node_url + "/node/submit_block/"
            block_data = request.POST.data

            try:
                requests.post(url=add_block_url, data=block_data)
            except Exception as e:
                print("There was an error propagating the block to %s" % peer.node_url)
                print(e)

        return HttpResponse("Block accepted")
    else:
        return HttpResponse("Only POST accepted")


def address_balance(request, address):
    balance = get_balance_address(address)
    return HttpResponse(balance)


def transaction_detail(request, tran_hash):
    transaction_requested = None
    for block in Block.objects.all():
        transaction = block.get_transaction(tran_hash)
        if transaction is not None:
            transaction_requested = transaction

    if transaction_requested:
        return HttpResponse(json.dumps(transaction_requested))
    else:
        return HttpResponse("No transaction found")


def all_transactions(request):
    transactions = []
    for block in Block.objects.all():
        transactions.append(block.transactions)

    return HttpResponse(json.dumps(transactions))


def blocks_detail(request):
    block_list = []
    genesis_block = GenesisBlock.objects.last()
    genesis_block_data = {
        'index': genesis_block.index,
        'difficulty': genesis_block.difficulty,
        'mined_by': genesis_block.mined_by,
        'nonce': genesis_block.nonce,
        'date_created': genesis_block.date_created.isoformat(),
    }
    block_list.append(genesis_block_data)

    for block in Block.objects.all():
        block_list.append({
            'index': block.index,
            'block_hash': block.block_hash,
            'block_data_hash': block.block_data_hash,
            'prev_block_hash': block.prev_block_hash,
            'difficulty': block.difficulty,
            'transactions': json.loads(block.transactions),
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
        'date_created': block.date_created.isoformat()
    }

    return HttpResponse(json.dumps(block_data))
