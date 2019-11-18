from django.contrib import admin

from blocks.models import Block, BlockCandidate, GenesisBlock
# Register your models here.
admin.site.register(Block)
admin.site.register(BlockCandidate)
admin.site.register(GenesisBlock)
