"""blockchain_django URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from node import views as node_views
from wallet import views as wallet_views

urlpatterns = [
    path('admin/', admin.site.urls),
    # path('/'),
    path('debug/', node_views.debug, name='debug'),  # TODO show all blockchain info here
    path('start_node/', node_views.start_node, name='start_node'),
    path('debug/reset_chain/', node_views.reset_chain, name='reset_chain'),
    path('wallets/', wallet_views.home, name='wallet_home'),
    path('wallet/new/', wallet_views.new_wallet, name='new_wallet'),
    path('wallet/<slug:address>/', wallet_views.wallet_home, name='wallet_home'),
    path('wallet/generate_transaction/<slug:address>/', wallet_views.generate_transaction, name='generate_transaction'),
    path('blocks/', node_views.blocks_detail, name='blocks_detail'),
    path('blocks/<int:index>/', node_views.block_index, name='block_index'),
    path('transactions/pending/', node_views.pending_transactions, name='pending_transactions'),
    path('transactions/confirmed/', node_views.confirmed_transactions, name='confirmed_transactions'),
    path('balances/', node_views.balances, name='balances'),  # TODO loop over addresses and calculate balances.
    path('address/<slug:address>/balance/', node_views.address_balance, name='address_balance'),
    path('transactions/add/', node_views.add_transaction_mempool, name='add_transaction'),
    path('transactions/<slug:tran_hash>/', node_views.transaction_detail, name='transaction_detail'),  # TODO all the transactions
    path('transactions/', node_views.all_transactions, name='all_transactions'),
    path('peers/', node_views.peers, name='peers'),
    path('peers/connect/', node_views.connect_peer, name='connect_peer'),
    path('peers/sync/', node_views.sync_blockchain_peer, name='sync_peer'),
    # path('peers/notify-new-block'), # TODO peer connection functionality is completely missing
    path('mining/get-mining-job/<slug:miner_address>/', node_views.generate_block_candidate, name='generate_block_candidate'),
    path('mining/submit_mined_block/', node_views.add_block, name='add_block'),  # The local miner submits block
    path('node/submit_block/', node_views.add_new_block, name='add_new_block')  # other node propagates block
]
