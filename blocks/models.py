from django.db import models


class GenesisBlock(models.Model):
    # A Singleton

    def save(self, *args, **kwargs):
        self.pk = 1
        super(GenesisBlock, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass


class Block(models.Model):
    pass
