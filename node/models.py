from django.db import models


# Create your models here.
class Node(models.Model):
    node_id = models.CharField(blank=True, max_length=150)
    peers = models.CharField(blank=True, max_length=5000)  # Keeps peer ids in json


class Peer(models.Model):
    related_node = models.ForeignKey(Node, blank=True, null=True, on_delete=models.CASCADE)  # local node
    node_id = models.CharField(blank=True, max_length=150, unique=True)
    node_url = models.CharField(blank=True, max_length=150)
