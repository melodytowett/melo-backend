
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from django.core.validators import RegexValidator
from django.contrib.auth import get_user_model
from django.forms import DateField
from location_field.models.plain import PlainLocationField
from rest_framework.authtoken.models import Token
from datetime import datetime


# Create your models here.


class User(AbstractUser):
    # is_manager =models.BooleanField(default=False)
    # is_merchandiser =models.BooleanField(default=False)
    # def __str__(self):
    #     return self.username

    # @receiver(post_save, sender=settings.AUTH_USER_MODEL)
    # def create_auth_token(sender, instance=None, created=False, **kwargs):
    #     if created:
    #         Token.objects.create(user=instance)
    name = models.CharField(max_length=100,blank=True,null=True)
    email = models.CharField(max_length=255, unique=True,blank=True,null=True)
    password = models.CharField(max_length=255,blank=True,null=True)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []



User = get_user_model()
phone_number_validator = RegexValidator(
    regex=r'^[0-9 \(\)]{10,12}$', message="Phone numbers must begin with +2547.... or 07..."
)



class Merchandiser(models.Model):
    user= models.OneToOneField(User,on_delete=models.CASCADE,related_name='merchandiser',blank=True,null=True)
    username = models.CharField(max_length=40,blank=True,null=True)
    phone_number = models.CharField(max_length=15, validators=[phone_number_validator],blank=True,null=True)
    email = models.EmailField(blank=True,null=True)
    location = PlainLocationField(based_fields=['city'], zoom=7,blank=True,null=True)

    def __str__(self):
        return str(self.user)

    def save_merch(self):
        self.save()

class Manager(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE, related_name='manager',blank=True,null=True)
    name = models.CharField(max_length=40,blank=True,null=True)
    description = models.TextField(blank=True,null=True)
    phone_number = models.CharField(max_length=15, validators=[phone_number_validator],blank=True,null=True)
    location = PlainLocationField(based_fields=['city'], zoom=7,blank=True,null=True)

    def __str__(self):
        return str(self.name)


class Address(models.Model):
    city = models.CharField(max_length=255,blank=True,null=True)
    location = PlainLocationField(based_fields=['city'], zoom=7,blank=True,null=True)
    date = models.DateTimeField(default=datetime.now, blank=True)

    def __str__(self):
        return self.city

    def save_address(self):
        self.save()

class Comment(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    comment = models.ForeignKey(Address,on_delete=models.CASCADE,related_name="comments", default="",blank=True,null=True)
    date = models.DateTimeField(auto_now_add=True,blank=True,null=True)
    content = models.TextField(blank=True,null=True)
    
    def __str__(self):
        return str(self.user.user)

    def save_comment(self):
        self.save()

