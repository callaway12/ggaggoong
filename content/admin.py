from django.contrib import admin
from user.models import Host, User
from content.models import Contents, Contents_Detail


admin.site.register(Contents)
admin.site.register(Contents_Detail)

