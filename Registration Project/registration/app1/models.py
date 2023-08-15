from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class app1(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    Email = models.EmailField(unique=True)  # Change to EmailField and add unique=True
    Password = models.CharField(max_length=150)
    Password2 = models.CharField(max_length=150)
    Forget_password_token = models.CharField(max_length=150, default='not_set')

    def __str__(self) -> str:
        return self.user.username