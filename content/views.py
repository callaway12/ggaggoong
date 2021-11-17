from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest, JsonResponse
from content.models import Contents, Contents_Detail
from faq.models import FAQ, FAQ_Answer
from content.models import Reserve
from user.models import User, Host
from django.contrib             import messages
import json
from collections import defaultdict

detail_count = {
    "count": 0,
}
def pay_page(request):
    return render(request,'content/pay_page.html')

def reserve(request, content_number):
    tmp_reserve = Reserve.objects.filter(content_id=content_number, reserve_alive=True)
    content = Contents.objects.get(id=content_number)
    if len(tmp_reserve) > content.people_number:
        print('more than the number')
        messages.warning(request, "more than the number")
        return redirect(f'/content/page/{content_number}', content_number)
    else:
        print('else')
        reserve = Reserve()
        reserve.content_id = content
        reserve.reserve_user = User.objects.get(id=request.user.id)
        reserve.save()
        print(reserve)
    reserves = Reserve.objects.filter(content_id=content_number)
    return render(request, 'content/pay_page.html', {'reserves':reserves, 'content':content})

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
            new_content.host_id = Host.objects.get(user_id=request.user.id)
            new_content.save()

            id_number = new_content
            content_number = new_content.id
            for j in range(int(request.POST.get("detail_count"))):
                new_detail_content = Contents_Detail()
                new_detail_content.contents_id = id_number
                new_detail_content.detail = request.POST.get(f"detail_{j}")
                new_detail_content.detail_img = request.FILES.get(f"detail_img_{j}")
                new_detail_content.host_id = Host.objects.get(user_id=request.user.id)
                new_detail_content.save()
            print('contetnt number : ', content_number)
            return redirect(f'/content/page/{content_number}', content_number)
        else:
            context["error"] = "정확히 모두 입력바랍니다."
            return JsonResponse(context, status=400)

    return render(request, "content/content_making.html", context)


def con_page(request, content_number):
    new_content = Contents.objects.get(id=content_number)
    # print(new_content.title_name)
    reserves = Reserve.objects.filter(content_id=content_number, reserve_alive=True)
    # print(len(reserves))
    faq = FAQ.objects.filter(faq_content=content_number).order_by('-created_at')
    # faq_id = FAQ.objects.filter(faq_content=content_number).values_list('id', flat=True)
    # faq_answers = FAQ_Answer.objects.filter(question_id__in=faq_id).order_by('-created_at')
    faq_answers = FAQ_Answer.objects.filter(question_id__in=faq).order_by('-created_at')
    # faq_answers = []
    faq_list = []
    # print('afdssdfasd')
    for faq_question in faq:
        # faq_answers.append(faq_question.answer.order_by('-created_at')[0])

        faq_list.append([faq_question,])
    for idx, fa in enumerate(faq_list):
        for ans in faq_answers:
            if ans.question_id == fa[0]:
                faq_list[idx] = [fa[0],ans]
    
    # print(faq_list)

    # 결제하기 버튼 clickable flag 값 생성해야함 
    reserve_available = False
    host_flag = False
    reserve_flag = Reserve.objects.filter(content_id=content_number, reserve_user=request.user.id)
    if reserve_flag:
        reserve_available = False
    else:
        reserve_available = True
    if new_content.host_id.id == request.user.id:
        host_flag = True
    else:
        host_flag = False
    # print('new_content.host_id : ', new_content.host_id.id)
    # print('request.user.id : ', request.user.id)
    context = {
        "new_content": new_content,
        "new_detail_content": [],
        "faqs" : faq,
        "faq_len" : len(faq),
        "reserves_len" : len(reserves),
        "faq_answers" : faq_answers,
        "faq_list" : faq_list,
        "reserve_available" : reserve_available,
        "host_flag" : host_flag,
    }
    for item in Contents_Detail.objects.filter(contents_id=content_number):
        context["new_detail_content"].append(item)

    return render(request, "content/content_page.html", context)

