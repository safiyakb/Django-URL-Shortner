from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class UrlTable(models.Model):
    title = models.CharField(max_length = 100, null = True, blank = True)
    long_url = models.CharField(max_length=100, null = True, blank=True)
    short_hash = models.CharField(max_length=10, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    no_clicks = models.IntegerField(default=0, null=True, blank=True)
    def __str__(self):
        return f"{self.short_hash} | {self.user.username}"