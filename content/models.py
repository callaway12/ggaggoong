from django.db import models
from user.models import User, Host

# Create your models here.
class Contents(models.Model):
    title_img = models.ImageField(
        upload_to="content/image/",
        blank=True,
        null=True
    )
    title_name = models.CharField(max_length=100)
    sub_title_name = models.CharField(max_length=100)
    content_date = models.DateTimeField()
    duration = models.IntegerField()
    location = models.CharField(max_length=100)
    people_number = models.IntegerField()
    age_min = models.IntegerField()
    age_max = models.IntegerField()
    price = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # host_id = models.Foreignkey('Host.user_id', on_delete=models.CASCADE, null=True)

class Contents_Detail(models.Model):
    detail = models.CharField(max_length=500)
    detail_img = models.ImageField(
        upload_to="content/detail_image/",
        blank=True,
        null=True
    )
    contents_id = models.ForeignKey('Contents', on_delete=models.CASCADE, null=True)
    # host_id = models.Foreignkey('Contents.host_id', on_delete=models.CASCADE, null=True)

