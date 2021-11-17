from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
import user.views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', user.views.home, name='home'),
    path('/', include('user.urls')),
    path('content/', include('content.urls')),
    path('faq/', include('faq.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
