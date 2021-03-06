import hashlib
import random
import requests
import time
import datetime


# node_id = input("node_id:")
node_id = "AnatolAnatolNode"
miner_address = "bc732f0a38bc6e50a0991a70f8d005201b2cf0ce"


def get_block_candidate(node_id):
    return requests.get("http://127.0.0.1:8000/mining/get-mining-job/" + node_id + "/")


def compare_proof_zeroes(possible_proof, num_zeroes):
    relevant_section = possible_proof[:num_zeroes]
    print("relevant_section: ", relevant_section)
    if relevant_section == "0" * num_zeroes:
        return True
    else:
        return False


def concat_header_nonce(block_data_hash, date_created, nonce):
    return hashlib.sha256((block_data_hash + date_created + str(nonce)).encode('utf-8')).hexdigest()


while True:
    nonce_found = False
    block_candidate = get_block_candidate(miner_address).json()
    print("NEW BLOCK CANDIDATE: ", block_candidate)
    block_data_hash = block_candidate['block_data_hash']
    print("block_data_hash: ", block_data_hash)
    difficulty = block_candidate['difficulty']
    print("difficulty: ", difficulty)

    while not nonce_found:
        # TODO include mining updates / timeout
        random_nonce = str(random.randrange(0, 99999999999999999))
        print("random_nonce: ", random_nonce)
        date_created = datetime.datetime.today().isoformat()
        possible_proof = concat_header_nonce(block_data_hash, date_created, random_nonce)
        print("possible_proof: ", possible_proof)
        if compare_proof_zeroes(possible_proof, difficulty):
            # Block Found!
            real_nonce = random_nonce
            # Send new block to node
            response = requests.post(url="http://127.0.0.1:8000/mining/submit_mined_block/",
                                     data={'nonce': real_nonce,
                                           'date_created': date_created,
                                           'block_data_hash': block_data_hash,
                                           'mined_by': miner_address})
            print("-----------------------block found!!!-----------------------")
            print(response.status_code)
            if response.status_code != 500:
                print(response.text)
            time.sleep(2)
            nonce_found = True
