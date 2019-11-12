
import base64
import json
import eth_keys, binascii
import hashlib
from merkletools import MerkleTools
from datetime import datetime


# from wallet.generate_transaction import generate_transaction

def generate_keys():
    private_key = eth_keys.keys.PrivateKey(binascii.unhexlify((hashlib.sha256(b"Led Zeppelin No Quarter")).hexdigest()))
    public_key = private_key.public_key
    pubkey_compressed = str(public_key)[2:66] + str(int(public_key) % 2)
    h = hashlib.new('ripemd160')
    h.update(pubkey_compressed.encode('utf-8'))
    address = h.hexdigest()

    # print('Private key (64 hex digits):', private_key)
    print('Public key (plain, 128 hex digits):', (public_key))
    print('public_key type:', type((public_key)))
    print('public_key len:', len((public_key)))
    # print('Public key (compressed):', pubkeyCompressed)
    # print('Signer address:', address)

    return {"private_key": private_key, "public_key": (public_key),
            "address": address}


def generate_transaction(first_wallet, second_wallet, value):
    print("------GENERATE-TRANSACTION--------")
    from_address = first_wallet['address']
    to_address = second_wallet['address']
    value = value
    fee = 1  # Hardcoded
    date_created = str(datetime.utcnow().isoformat())
    data = ""
    public_key = (first_wallet['public_key'].to_hex())

    transaction_data_json = json.dumps({'from': from_address, 'to': to_address, 'value': value,
                                        'fee': fee, 'date_created': date_created,
                                        'data': data, 'public_key': public_key})

    transaction_hash = hashlib.sha256(transaction_data_json.encode('utf-8'))

    # Sign the transaction hash with the sender private key
    sender_private_key = first_wallet['private_key']
    signature = sender_private_key.sign_msg(bytes(transaction_hash.hexdigest().encode('utf-8')))
    print("signature: %s" % signature)

    # Get the public key in the correct format
    public_key_bytes = first_wallet['public_key'].to_compressed_bytes()
    encoded_bytes = base64.b64encode(public_key_bytes)
    public_key_string = str(encoded_bytes)[1:].strip("'")

    # json_serialized_key = json.dumps({'pubkey': public_key_string})
    # public_key_string = (json.loads(json_serialized_key))['pubkey']
    # new_bytes = base64.b64decode('"' + public_key_string + '"')
    # public_key_again = eth_keys.keys.PublicKey.from_compressed_bytes(new_bytes)
    # signature.verify_msg(bytes(transaction_hash.hexdigest().encode('utf-8')), public_key_again)

    # final transaction json
    transaction_json = json.dumps({
        'from': from_address,
        'to': to_address,
        'value': value,
        'fee': fee,
        'date_created': date_created,
        'data': data,
        'public_key': public_key_string,
        'transaction_hash': transaction_hash.hexdigest(),
        'sender_signature': [signature.v, signature.r, signature.s],
        'mined_in_block_index': None,
        'transfer_successful': False
    })

    return transaction_json


def verify_transaction_signature(transaction):
    # transaction: json
    transaction = json.loads(transaction)
    public_key_string = transaction['public_key']
    transaction_hash = transaction['transaction_hash']
    signature_raw = transaction['sender_signature']
    print("signature_raw:")
    print(signature_raw)
    signature = eth_keys.keys.Signature(vrs=signature_raw)
    new_bytes = base64.b64decode('"' + public_key_string + '"')
    public_key = eth_keys.keys.PublicKey.from_compressed_bytes(new_bytes)

    return signature.verify_msg(bytes(transaction_hash.encode('utf-8')), public_key)


def create_pre_block_header(transaction_list, last_block_hash, miner_address, difficulty):
    # Create Merkle Tree
    merkle_tree = MerkleTools()
    for transaction in transaction_list:
        merkle_tree.add_leaf(json.loads(transaction)['transaction_hash'])

    merkle_tree.make_tree()
    merkle_root = None
    if merkle_tree.is_ready:
        merkle_tree.get_merkle_root()
    else:
        return False

    block_data_hash = hashlib.sha256(("1" + str(merkle_root) + str(difficulty) +
                                     str(last_block_hash) + str(miner_address)).encode('utf-8'))

    pre_block_header = {
        'index': 1,  # Hardcoded
        'hash_merkle_root': merkle_root,
        'bits': difficulty,
        'hash_prev_block': last_block_hash,
        'mined_by': miner_address,
        'block_data_hash': block_data_hash,
        'nonce': 0,
        'time': datetime.today().isoformat(),
    }

    print("pre_block_header:")
    print(pre_block_header)

    return pre_block_header


# TEST STUFF
first_wallet = generate_keys()
second_wallet = generate_keys()

transaction1_json = generate_transaction(first_wallet, second_wallet, 100)
transaction2_json = generate_transaction(first_wallet, second_wallet, 100)
transaction3_json = generate_transaction(first_wallet, second_wallet, 100)
transaction4_json = generate_transaction(first_wallet, second_wallet, 100)

print(verify_transaction_signature(transaction1_json))
print(verify_transaction_signature(transaction2_json))
print(verify_transaction_signature(transaction3_json))
print(verify_transaction_signature(transaction4_json))

transaction_list = [transaction1_json, transaction2_json, transaction3_json, transaction4_json]
create_pre_block_header(transaction_list, last_block_hash="sadlkjghSDLKGALSJDHFVGIASHDFVADJFHG",
                        miner_address="ksghdjvfiahsdvfisdvfoSDVFIOYSDV", difficulty=4)
