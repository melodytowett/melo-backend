from route.serializer import ManagerSignupSerializer,MerchandiserSignupSerializer,UserSerializer
from rest_framework import generics,status,permissions
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView
from route.permissions import IsManagerUser,IsMerchandiserUser
from route.models import Manager, Merchandiser


from .models import  Merchandiser,Manager,Comment, Address
from .serializer import MerchandiserSerializer,ManagerSerializer,RouteSerializer
from rest_framework import status
from .permissions import IsAdminOrReadOnly

# Create your views here.

class MerchandiserSignupView(generics.GenericAPIView):
    serializer_class =MerchandiserSignupSerializer
    
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
    serializer_class = ManagerSignupSerializer
    queryset = Manager.objects.all()

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
