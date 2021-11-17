from os import times
from django.shortcuts           import render
from django.contrib             import auth
# from ggaggoong.user.models      import Host
from user.models                import User, Host
from django.shortcuts           import render, redirect
from django.shortcuts           import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from datetime                   import datetime
from django.utils               import formats
from django.utils.dateformat    import DateFormat
from django.utils.formats       import get_format
import json, re
from django.http                import JsonResponse
from django.views               import View
from django.core.exceptions     import ValidationError
from django.contrib             import messages
import time, random, sys, traceback, logging, datetime
from content.models             import Contents, Contents_Detail, Reserve
from faq.models                 import FAQ, FAQ_Answer


# from .utils                     import validate_email, validate_password

def logout(request):
    if request.method == 'GET':
        auth.logout(request)
        redirect('home')
    return render(request,'home.html')

def home(request):
    host_flag = False
    try:
        Host.objects.get(user_id=request.user.id)
        host_flag = True
    except:
        pass
    contents = Contents.objects.all().order_by("-created_at")
    return render(request, 'home.html', {"contents":contents, "host_flag":host_flag})
# 회원가입
def signup(request):
    if request.method == 'POST':
        if request.POST['password1'] == request.POST['password2'] and len(request.POST['password1']) >= 5:
            try:
                
                if not validate_email(request.POST['email']):
                    return JsonResponse({'MESSAGE':'INVALID_EMAIL_ADDRESS'}, status=404)

                if not validate_password(request.POST['password1']):
                    return JsonResponse({'MESSAGE':'INVALID_PASSWORD'}, status=404)

            except KeyError:
                return JsonResponse({'MESSAGE':'KEY_ERROR'}, status=404)
            except ValidationError as e:
                return JsonResponse({'MESSAGE':e.message}, status=404)
            user = User.objects.create_user(
                    username=request.POST['mom_name'],
                    email=request.POST['email'],
                    mom_name=request.POST['mom_name'],
                    password=request.POST['password1'],
                    baby_name=request.POST['baby_name'],
                    baby_gender=request.POST['baby_gender'],
                    baby_birth=request.POST.get('baby_birth'),
                    phone=request.POST['phone_num'],
                    address=request.POST['address'],
                    
                    )
            if user is not None:
                auth.login(request, user)
                return redirect('/user/home') #render(request, 'home.html', {'user':user})
    elif request.method == "GET" and request.user.id:
        return redirect('/user/home')
    print("회원가입 안됨")
    return render(request, 'signup.html') 

@login_required
def host_signup(request):
    print(request.user.id)
    try:
        # host = Host()
        print('try')
        host = Host.objects.filter(user_id = request.user.id)
    except Host.DoesNotExist:
        print('except')
        host = None
    # if host is not None:
    #     print('if1')
    #     return render(request, 'host_signup.html', {'host' : Host.objects.filter(user_id = request.user.id)})
    if request.method == 'POST':
        print('if2')
        if request.user.id:
            print('if3')
            print(request.user.id)
            # user = User()
            host = Host()
            host.user_id = User.objects.get(id = request.user.id)
            host.id_card1 = request.POST["id_card1"]
            host.id_card2 = request.POST["id_card2"]            
            host.certificate_id = request.POST["certificate_id"]
            try: # request.FILES["crimelog"]:
                host.crimelog = request.FILES["crimelog"]
            except:
                pass
            host.crime_bool = request.POST["crime_bool"]
            try: # request.FILES["bank_img"]:
                host.bank_img = request.FILES["bank_img"]
            except:
                pass
            host.bank_num = request.POST["bank_num"]
            host.save()
            if host is not None:
                print('ssibal')
                # auth.login(request, user)
                return redirect('/user/home')
    print("회원가입 안됨")
    if request.method =='GET':
        if request.user.id is None:
            messages.warning(request, "회원가입 먼저 해주세요!")
            return redirect('signup')
        return render(request, 'host_signup.html')#redirect('signup')

def login(request):
    if request.method == 'GET':
        error_message = '로그인페이지입니다.'
        return render(request, 'login.html', {'error_message':error_message})
    elif request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = auth.authenticate(request, email=email, password=password)        
        if user is not None:
            auth.login(request, user)
            return redirect('/user/home')#render(request, 'home.html', {'user':user})
        elif user is None:
            messages.warning(request, "회원정보가 없습니다 회원가입해주세요")
    error_message = '잘못된 요청입니다. 다시 로그인해주세요.'  
    return render(request, 'login.html', {'error_message':error_message})


# def host_login(request):
#     if request.method == 'GET':
#         if Host.objects.get(id=request.user.id) is not None:
#             return render(request, 'host_login.html')
            
#         elif Host.objects.get(id=request.user.id) is None:
#             error_message = '호스트 로그인페이지입니다.'
#             return render(request, 'host_signup.html',{'error_message':error_message})
#     error_message = '잘못된 요청입니다. 다시 로그인해주세요.'  
#     return render(request, 'login.html', {'error_message':error_message})


def user_update(request):
    id = request.user.id
    user = User.objects.get(id=id)
    if request.method == 'POST':
        user.username=request.POST['mom_name'],
        user.email=request.POST['email'],
        user.mom_name=request.POST['mom_name'],
        user.password=request.POST['password1'],
        user.baby_name=request.POST['baby_name'],
        user.baby_gender=request.POST['baby_gender'],
        user.baby_birth=request.POST.get('baby_birth'),
        user.phone=request.POST['phone_num'],
        user.address=request.POST['address']

        user.save()
        return redirect('home.html')
    elif request.method == "GET":
        return render(request, "user_update.html", {"user":user})


def host_update(request):
    user_id = request.user.id
    host = Host.objects.get(user_id = user_id)
    if request.method == 'POST':
        print(request.user.id)
        host.user_id = get_object_or_404(User, id=request.user.id)
        host.id_card1 = request.POST["id_card1"]
        host.id_card2 = request.POST["id_card2"]            
        host.certificate_id = request.POST["certificate_id"]
        try: # request.FILES["crimelog"]:
            host.crimelog = request.FILES["crimelog"]
        except:
            pass
        host.crime_bool = request.POST["crime_bool"]
        try: # request.FILES["bank_img"]:
            host.bank_img = request.FILES["bank_img"]
        except:
            pass
        host.bank_num = request.POST["bank_num"]
        host.save()
        if host is not None:
            # auth.login(request, user)
            return redirect('/user/home')
    elif request.method == "GET":
        return render(request, "host_signup.html", {"host":host})

def validate_email(email):
        return re.match('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email) != None 

def validate_password(password):
        return len(password)>=5

def duplicate_email_check(email):
        return User.objects.filter(email=email).exists() 

def mypage(request):
    if request.method == "GET":
        # 호스트면 이거 보여주고 일반이면 안보여주고, 
        # to-do : 일반 사용자가 해당 컨텐츠에 지원하고 결제하는 부분까지 해야함
        try:
            # print(User.objects.get(id=request.user.id))
            # print(Contents.objects.filter(id=request.user.id))
            # print(FAQ.objects.filter(questioner=request.user.id))
            # host_contents = Contents.objects.filter(host_id=request.user.id).order_by('-created_at')
            user = User.objects.get(id=request.user.id)
            faqs = FAQ.objects.filter(questioner=request.user.id).order_by('-created_at')
            reserves = Reserve.objects.filter(reserve_user=request.user.id).order_by('-created_at')

            print(reserves.content_date)


            total_reserve_price = 0
            total_reserve_price_flag = False
            remain_reserves = []
            for reserve in reserves:
                total_reserve_price += reserve.price
                print('remain')
                if reserve.content_date > datetime.datetime.now():
                    remain_reserves.append(reserve)
                    print(reserve.content_date)
                    print(datetime.datetime.now())
            print(remain_reserves)

            if total_reserve_price > 0:
                total_reserve_price_flag = True

            reserves_len_flag = False
            reserves_len = len(reserves)
            if reserves_len> 0:
                reserves_len_flag = True

            host_flag = False
            host_contents_flag = False
            if Host.objects.get(user_id = request.user).exist():
                host_flag = True
                host = Host.objects.get(user_id = request.user)
                if Contents.objects.get(host_id = host).exist():
                    host_contents_flag = True
                    host_contents = Contents.objects.get(host_id = host).exist()
            

            
            
            context= {
                'user' : user,
                'host_contents' : host_contents,
                'faqs' : faqs,
                'host_flag' : host_flag,
                'host_contents_flag' : host_contents_flag,
                'reserves' : reserves,
                'total_reserve_price' : total_reserve_price,
                'total_reserve_price_flag' : total_reserve_price_flag,
                'reserves_len' : reserves_len,
                'reserves_len_flag' : reserves_len_flag,
            }
            return render(request, 'mypage.html', context)
        except:
            messages.warning(request, "회원가입 먼저 해주세요!")
            return render(request, 'mypage.html')
        
def host_mypage(request):
    # 노필요 
    if request.method == "GET":
        try:

            host = Host.objects.get(user_id=request.user.id)
            print(host)
            context= {
                'host':host
            }
            return render(request, 'mypage.html', context)
        except:
            messages.warning(request, "회원가입 먼저 해주세요!")
            return render(request, 'login.html')