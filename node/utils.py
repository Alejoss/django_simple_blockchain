import json
from datetime import datetime
import hashlib

from django.conf import settings

from transactions.models import Transaction
from blocks.models import Block


def compare_proof_zeroes(possible_proof, num_zeroes):
    relevant_section = possible_proof[:num_zeroes]
    print("relevant_section: ", relevant_section)
    if relevant_section == "0" * num_zeroes:
        return True
    else:
        return False


def concat_header_nonce(block_data_hash, date_created, nonce):
    return hashlib.sha256((block_data_hash + date_created + str(nonce)).encode('utf-8')).hexdigest()


def serialize_transactions(transaction_list, coinbase_transaction=None):
    # receives Transaction objects, returns json
    print("```````````````````````````serialize_transactions````````````````````````")
    serialized_list = []
    for transaction in transaction_list:
        serialized_list.append(
            {
                'from_address': transaction.from_address,
                'to_address': transaction.to_address,
                'value': transaction.value,
                'fee': transaction.fee,
                'date_created': transaction.date_created.isoformat(),
                'data': transaction.data,
                'sender_public_key': transaction.sender_public_key,
                'transaction_data_hash': transaction.transaction_data_hash,
                'sender_signature': transaction.sender_signature,
                'mined_in_block_index': transaction.mined_in_block_index,
                'transfer_successful': transaction.transfer_successful
            }
        )
    print("serialized_list1:")
    print(serialized_list)
    if coinbase_transaction:
        serialized_list.append(coinbase_transaction)
    print("serialized_list2:")
    print(serialized_list)
    print("```````````````````````````````````````````````````````````````````````")
    return json.dumps(serialized_list)


def generate_coinbase_transaction(miner_address, block_index):
    transaction = {"from_address": settings.GENESIS_ADDRESS,
                   "to_address": miner_address,
                   "value": str(5000350),
                   "fee": str(0),
                   "date_created": datetime.today().isoformat(),
                   "data": "coinbase tx",
                   "public_key": "0000000000000000000000000000000000000000",
                   "sender_signature": ["0000000000…0000", "0000000000…0000"],
                   "mined_in_block_index": str(block_index),
                   "transfer_succesful": False
                   }

    transaction["transaction_data_hash"] = hashlib.sha256(
        (transaction["from_address"] + transaction["to_address"] + transaction["value"]
         + transaction["date_created"] + transaction["fee"] + transaction["data"] +
         transaction["public_key"]).encode('utf-8')).hexdigest()

    Transaction.objects.create(
        from_address=transaction['from_address'],
        to_address=transaction['to_address'],
        value=transaction['value'],
        fee=transaction['fee'],
        date_created=transaction['date_created'],
        data=transaction['data'],
        sender_public_key=transaction['public_key'],
        transaction_data_hash=transaction['transaction_data_hash'],
        sender_signature=transaction['sender_signature'],
        mined_in_block_index=None,
        transfer_successful=False
    )
    return transaction


def get_balance_address(address):
    balance = 0
    transactions_address = []
    for block in Block.objects.all():
        transactions_address.extend(block.get_transactions_address(address))
    # TODO values can never be negative
    for transaction in transactions_address:
        if transaction["from_address"] == address:
            print("from")
            print(transaction["from_address"])
            print(transaction["value"])
            balance -= int(transaction["value"])
        elif transaction["to_address"]:
            print("to")
            print(transaction["to_address"])
            print(transaction["value"])
            balance += int(transaction["value"])
    return balance


def get_all_addresses():
    addresses = [settings.GENESIS_ADDRESS]
    for b in Block.objects.all():
        for t in json.loads(b.transactions):
            print(t)
            if t['from_address'] not in addresses:
                addresses.append(t['from_address'])
            elif t['to_address'] not in addresses:
                addresses.append(t['to_address'])

    return addresses
