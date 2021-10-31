from django.urls import path

from content import views

urlpatterns = [
    path("make/", views.con_making),
    path("page/<int:content_number>/", views.con_page),

]