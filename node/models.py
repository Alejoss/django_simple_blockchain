from django.db import models


# Create your models here.
class Node(models.Model):
    node_id = models.CharField(blank=True, max_length=150)
    miner_address = models.CharField(blank=True, max_length=150)
    peers = models.CharField(blank=True, max_length=5000)  # Keeps peer ids in json

