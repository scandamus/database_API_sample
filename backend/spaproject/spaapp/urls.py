from django.urls import path
from . import views

urlpatterns = [
    path('getUserProfile', views.getUserProfile),
    path('api/user/<str:username>/', views.getUserProfile, name='getUserProfile'),
    path('api/userProfile/', views.userProfile, name='userProfile'),
    path('api/register/', views.registerUser, name='registerUser'),
    path('api/login/', views.loginUser, name='loginUser'),
    path('api/logout/', views.logoutUser, name='logoutUser'),
    path('api/check_login/', views.check_login_status, name='check_login'),
    path('api/delete/', views.deleteUser, name='deleteUser'),
]