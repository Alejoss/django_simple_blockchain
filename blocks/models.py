from django.db import models


class GenesisBlock(models.Model):
    # A Singleton

    def save(self, *args, **kwargs):
        self.pk = 1
        super(GenesisBlock, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass


class Block(models.Model):
    block_hash = models.CharField(blank=True, max_length=150)
    difficulty = models.SmallIntegerField(null=True)
    # TODO falta todos los campos, el nodo utiliza latest()

