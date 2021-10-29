from django.urls import path

from content import views

urlpatterns = [
    path("content_make/", views.content_making),
    path("content/page/", views.content_page),

]