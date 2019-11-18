from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse

from wallet.models import Wallet


def home(request):
    all_wallets = Wallet.objects.all()

    return render(request, "wallets_home.html", {'all_wallets': all_wallets})


def new_wallet(request):
    if request.method=="POST":
        passphrase = request.POST.get("passphrase")
        wallet = Wallet.objects.create()
        wallet.generate_keys(passphrase.encode('utf-8'))
    else:
        return HttpResponse('Only POST')

    return render(request, "wallet.html", {'wallet': wallet, 'message': 'NEW WALLET CREATED'})


def wallet_home(request, address):
    wallet = Wallet.objects.get(address=address)

    return render(request, 'wallet.html', {'wallet': wallet})


def generate_transaction(request, address):
    wallet_sender = Wallet.objects.get(address=address)
    destination_address = request.POST.get("destination_address")
    value = int(request.POST.get("value"))

    transaction_json = wallet_sender.generate_transaction(destination_address, value)

    return render(request, 'transaction_ready.html', {'transaction_json': transaction_json})
