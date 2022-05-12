from importlib_resources import contents
from route.serializer import ManagerSignupSerializer,MerchandiserSignupSerializer,UserSerializer
from rest_framework import generics,status,permissions
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView
from route.permissions import IsManagerUser,IsMerchandiserUser
from route.models import Manager, Merchandiser
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import SessionAuthentication, BasicAuthentication,TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import  Merchandiser,Manager,Comment, Address, User
from .serializer import MerchandiserSerializer,ManagerSerializer,RouteSerializer,UserSerializer
from rest_framework import status
from .permissions import IsAdminOrReadOnly
from rest_framework.exceptions import AuthenticationFailed
from .models import User
import jwt, datetime

# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    def get (self,request):
        ''''
        '''


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response

    def get(self,request):
        ''''
        '''


class UserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response

class MerchandiserSignupView(generics.GenericAPIView):
    queryset = Merchandiser.objects.all()
    serializer_class =MerchandiserSignupSerializer
    authentication_classes = (TokenAuthentication)
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        content = {
            'user':str(request.user),
            'auth':str(request.auth),

        }
        return Response(content)
        
    def post(self,request,*args,**kwargs):
        serializer=self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user=serializer.save()
        # token = Token.objects.create(user)
        return Response({
            'user':UserSerializer(user,context=self.get_serializer_context()).data,
            'token':Token.objects.get(user=user).key,
            'message':'account succesfully created'
           
        })

class ManagerSignupView(generics.GenericAPIView):
    queryset = Manager.objects.all()
    serializer_class =ManagerSignupSerializer
    # authentication_classes = [SessionAuthentication, BasicAuthentication]
    # permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        content = {
            'user':str(request.user),
            'auth':str(request.auth),
        }
        return Response(content)

    def post(self,request,*args,**kwargs):
        serializer=self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user=serializer.save()
        return Response( {
           'user':UserSerializer(user,context=self.get_serializer_context()).data,
            'token':Token.objects.get(user=user).key,
            'message':'account succesfully created'
        })
class CustomAuthToken(ObtainAuthToken):

    def post(self,request,*args,**kwargs):
        serializer=self.serializer_class(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)
        user=serializer.validated_data['user']
        token,created=Token.objects.get_or_create(user=user)
        return Response({
            'token':token.key,
            'user_id':user.pk,
            'is_manager':user.is_manager,
            'is_merchandiser':user.is_merchandiser
        })
class LogoutView(APIView):
    def post(self,request,format=None):
        request.auth.delete()
        return Response(status=status.HTTP_200_OK)

class ManagerOnlyView(generics.RetrieveAPIView):
    permission_classes=[permissions.IsAuthenticated&IsManagerUser]
    serializer_class=UserSerializer

    def get_object(self):
        return self.request.user

class MerchandiserOnlyView(generics.RetrieveAPIView):
    permission_classes=[permissions.IsAuthenticated&IsMerchandiserUser]
    serializer_class=UserSerializer

    def get_object(self):
        return self.request.user


class MerchandiserList(APIView):
    def get(self, request, format=None):
        merch = Merchandiser.objects.all()
        serializers = MerchandiserSerializer(merch, many=True)
        return Response(serializers.data)

    def post(self, request, format=None):
        serializers = MerchandiserSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            return Response(serializers.data, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)
    # permission_classes = (IsAdminOrReadOnly,)

class ManagerList(APIView):
    def get(self, request, format=None):
        manager = Manager.objects.all()
        serializers = ManagerSerializer(manager, many=True)
        return Response(serializers.data)

    def post(self, request, format=None):
        serializers = ManagerSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            return Response(serializers.data, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)
    # permission_classes = (IsAdminOrReadOnly,)

class RouteList(APIView):
    def get(self, request, format=None):
        routes = Address.objects.all()
        serializers = RouteSerializer(routes, many=True)
        return Response(serializers.data)
        
    def post(self, request, format=None):
        serializers = RouteSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            return Response(serializers.data, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)
    # permission_classes = (IsAdminOrReadOnly,)
