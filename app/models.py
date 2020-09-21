from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    address = models.TextField()
    DOB = models.DateField()
    user = models.ForeignKey(User, related_name="UserProfile", on_delete=models.CASCADE)


