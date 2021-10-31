from django.contrib import admin
from django.urls import path
from user import views
urlpatterns = [
    path('signup/', views.signup, name="signup"),
    path('home/', views.home, name="home"),
    # path('accounts/kakao/login/', views.kakao_login, name='kakao_login'),
    # path('accounts/kakao/callback/', views.kakao_callback, name='kakao_callback'),
    # path('accounts/kakao/login/finish/', views.KakaoLogin.as_view(), name='kakao_login_todjango'),
    # path('kakao/login/', views.kakaoGetLogin),
    # path('kakao/login/callback', views.kakaoCallback),
    # path("login/kakao/", views.kakao_login, name="kakao-login"),
    # path(
    #     "login/kakao/callback/",
    #     views.kakao_login_callback,
    #     name="kakao-callback",
    # ),
]
