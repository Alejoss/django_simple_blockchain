"""django_blockchain URL Configuration

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

urlpatterns = [
    path('admin/', admin.site.urls),
    path('/'),
    # path('/debug'),
    path('/debug/reset-chain', node_views.reset_chain, name='reset_chain'),
    # path('/blocks'),
    # path('/blocks/index'),
    # path('/transactions/pending'),
    # path('/transactions/confirmed'),
    # path('/transactions/tran_hash'),
    # path('/balances'),
    # path('/address/address/balance'),
    # path('/transactions/send'),
    # path('/peers/'),
    # path('/peers/connect/'),
    # path('peers/notify-new-block'),
    # path('/mining/get-mining-job/address'),
    # path('/mining/submit-mined-block')
]
