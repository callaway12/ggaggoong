from django.contrib import admin
from django.urls import path, include
from user import views
urlpatterns = [
    path('signup/', views.signup, name="signup"),
    path('home/', views.home, name="home"),
    # path('naverlogin/', views.naver_login, name='naver_login'),
    path('kakao_login/', views.kakao_login, name="kakao_login"),
    path('kakao_callback/', views.kakao_callback, name="kakao_callback"),

]
