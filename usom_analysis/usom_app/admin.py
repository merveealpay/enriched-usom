from django.contrib import admin
from .models import DomainIP

@admin.register(DomainIP)
class DomainIPAdmin(admin.ModelAdmin):
    list_display = ['domain', 'ip', 'similar_iocs', 'whois_info']