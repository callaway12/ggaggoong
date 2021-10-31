from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from content.models import Contents, Contents_Detail


def con_making(request):
    context = {

    }
    if request.method == "POST":
        if (
                request.POST.get("title_name") and
                request.POST.get("sub_title_name") and
                request.POST.get("title_image") and
                request.POST.get("content_date") and
                request.POST.get("duration") and
                request.POST.get("sub_title_name") and
                request.POST.get("people_number") and
                request.POST.get("age_min") and
                request.POST.get("age_max") and
                request.POST.get("price") and
                request.POST.get("detail_img") and
                request.POST.get("detail")
        ):
            new_content = Contents()
            new_content.title_name = request.POST.get("title_name")
            new_content.sub_title_name = request.POST.get("sub_title_name")
            new_content.title_img = request.POST.get("title_img")
            new_content.content_date = request.POST.get("content_date")
            new_content.duration = request.POST.get("duration")
            new_content.location = request.POST.get("location")
            new_content.people_number = request.POST.get("people_number")
            new_content.age_min = request.POST.get("age_min")
            new_content.age_max = request.POST.get("age_max")
            new_content.price = request.POST.get("price")
            new_content.save()

            new_detail_content = Contents_Detail()
            id_number = new_content
            new_detail_content.contents_id = id_number
            new_detail_content.detail = request.POST.get("detail")
            new_detail_content.detail_img = request.POST.get("detail_img")
            new_detail_content.save()

            return redirect("admin")
        else:
            context["error"] = "정확히 모두 입력바랍니다."


    return render(request, "content/content_making.html", context)


def con_page(request, content_number):
    new_content = Contents.objects.get(id=content_number)
    print(new_content.title_name)
    new_detail_content = Contents_Detail.objects.get(contents_id=content_number)

    return render(request, "content/content_page.html")


# Create your views here.
