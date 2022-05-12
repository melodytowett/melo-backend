from django.urls import path
from route.views import CustomAuthToken,ManagerSignupView,MerchandiserSignupView,LogoutView,LoginView,UserView,RegisterView
from . import views

app_name = 'route'
urlpatterns = [
    path('signup/manager/',ManagerSignupView.as_view()),
    path('signup/merchandiser/',MerchandiserSignupView.as_view()),
    path('login/',CustomAuthToken.as_view(),name='auth-token'),
    path('logout/',LogoutView.as_view(),name='logout=view'),
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('api/merchandiser/', views.MerchandiserList.as_view()),
    path('api/manager/', views.ManagerList.as_view()),
    path('api/routes/', views.RouteList.as_view()),
]