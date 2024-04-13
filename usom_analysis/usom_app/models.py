from django.db import models

class DomainIP(models.Model):
    domain = models.CharField(max_length=255, unique=True)
    ip = models.CharField(max_length=255, null=True, blank=True)
    whois_info = models.TextField(null=True, blank=True)
    similar_iocs = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.domain

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
