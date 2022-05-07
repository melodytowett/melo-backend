from rest_framework import serializers
from route .models import Manager,Merchandiser,User,Address
from rest_auth.registration.serializers import RegisterSerializer
from django.contrib.auth import authenticate

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['username','email','is_manager','is_merchandiser']

class MerchandiserSignupSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type":"password2"}, write_only=True)
    class Meta:
        model = User
        fields=['username', 'email', 'password','password2']
        extra_kwargs={
            'password':{'write_only':True}
        }
    def save(self, **kwargs):
        user=User(
            username=self.validated_data['username'],
            email=self.validated_data['email']
        )
        password=self.validated_data['password']
        password2=self.validated_data['password2']
        if password !=password2:
            raise serializers.ValidationError({"error":"password do not match"})
        user.set_password(password)
        user.is_merchandiser=True
        user.save()
        Merchandiser.objects.create(user=user)
        return user

class LoginMechSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self,data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError('incorrect credentials')

class ManagerSignupSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={"input_type":"password2"},write_only=True)
    class Meta:
        model=User
        fields=['username','email','password','password2']
        extra_kwargs={
            'password':{'write_only':True}
        }
  
    def save(self, **kwargs):
            user=User(
                username=self.validated_data['username'],
                email=self.validated_data['email']
            )
            password=self.validated_data['password']
            password2=self.validated_data['password2']
            if password !=password2:
                raise serializers.ValidationError({"error":"password do not match"})
            user.set_password(password)
            user.is_manager=True
            user.save()
            Manager.objects.create(user=user)
            return user
    


class MerchandiserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchandiser
        fields = ('username', 'phone_number','email', 'location')

class ManagerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manager
        fields = ("name", "description", "phone_number", "location")

class RouteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ('city', 'location')
