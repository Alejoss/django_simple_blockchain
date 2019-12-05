Run Migrations (python manage.py migrate)
Start Node (start_node/)
Reset Chain (debug/reset_chain/)
Create 2 Wallets (wallets/)
Copy the address of one wallet and paste it in miner.py miner_address
Make sure there are no blocks mined in /blocks/
Set difficulty in settings.DIFFICULTY
Mine a couple of blocks running miner.py in django_blockchain/
Check miner balance in address/<slug:address>/balance
Send a transaction from the miner to other address
Check the transaction in the memepool transactions/pending/
Mine a block
Make sure the transaction is not in the memepool anymore
Make sure the transaction is confirmed transactions/confirmed/
Check transaction detail transactions/<slug:tran_hash>/
