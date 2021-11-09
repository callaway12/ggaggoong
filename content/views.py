from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest, JsonResponse
from content.models import Contents, Contents_Detail
import json

detail_count = {
    "count": 0,
}


def con_making(request):

    context = {

         }       
    if_check_detail_img = []
    if_check_detail = []
    if request.method == "POST":
        # request_body = json.loads(request.body)
        for i in range(int(request.POST.get("detail_count"))):
            if_check_detail_img.append(request.FILES.get(f"detail_img_{i}"))
            if_check_detail.append(request.POST.get(f"detail_{i}"))

        if (
                request.POST.get("title_name") and
                request.POST.get("sub_title_name") and
                request.FILES.get("title_image") and
                request.POST.get("content_date") and
                request.POST.get("duration") and
                request.POST.get("location") and
                request.POST.get("people_number") and
                request.POST.get("age_min") and
                request.POST.get("age_max") and
                request.POST.get("price") and
                len(if_check_detail) == int(request.POST.get("detail_count")) and
                len(if_check_detail_img) == int(request.POST.get("detail_count"))
        ):
            process = True
        else:
            process = False

        for i in range(int(request.POST.get("detail_count"))):
            if(
                    request.FILES.get(f"detail_img_{i}") and
                    request.POST.get(f"detail_{i}")
            ):
                process = True
            else:
                process = False

        if process:
            new_content = Contents()
            new_content.title_name = request.POST.get("title_name")
            new_content.sub_title_name = request.POST.get("sub_title_name")
            new_content.title_img = request.FILES.get("title_image")
            new_content.content_date = request.POST.get("content_date")
            new_content.duration = request.POST.get("duration")
            new_content.location = request.POST.get("location")
            new_content.people_number = request.POST.get("people_number")
            new_content.age_min = request.POST.get("age_min")
            new_content.age_max = request.POST.get("age_max")
            new_content.price = request.POST.get("price")
            new_content.save()

            id_number = new_content

            for j in range(int(request.POST.get("detail_count"))):
                new_detail_content = Contents_Detail()
                new_detail_content.contents_id = id_number
                new_detail_content.detail = request.POST.get(f"detail_{j}")
                new_detail_content.detail_img = request.FILES.get(f"detail_img_{j}")
                new_detail_content.save()
            return redirect("/admin/")
        else:
            context["error"] = "정확히 모두 입력바랍니다."
            return JsonResponse(context, status=400)

    return render(request, "content/content_making.html", context)


def con_page(request, content_number):
    new_content = Contents.objects.get(id=content_number)
    print(new_content.title_name)
    context = {
        "new_content": new_content,
        "new_detail_content": []
    }
    for item in Contents_Detail.objects.filter(contents_id=content_number):
        context["new_detail_content"].append(item)

    return render(request, "content/content_page.html", context)

