from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # path('user/', include('user.urls')),
    # path('user/', include('allauth.urls')),
    path('user/', include('dj_rest_auth.urls')),
    path('accounts/', include('allauth.urls')),
    path('user/', include('user.urls')),
]
