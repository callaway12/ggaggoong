from django.shortcuts           import render
from django.contrib             import auth
from requests.models import Response
from user.models                import User
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
# from .utils                     import validate_email, validate_password
from ggaggoong.settings import SOCIAL_OUTH_CONFIG
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.shortcuts import redirect, reverse
from django.contrib import messages
import os, requests
from django.conf import settings







def home(request):
    return render(request, 'home.html')
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
                return redirect('/user/home')
    return render(request, 'signup.html') 



def validate_email(email):
        return re.match('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email) != None 

def validate_password(password):
        return len(password)>=5

def duplicate_email_check(email):
        return User.objects.filter(email=email).exists() 


# def kakao_login(request):
#     rest_api_key = getattr(settings, 'KAKAO_REST_API_KEY')
#     return redirect(
#         f"https://kauth.kakao.com/oauth/authorize?client_id={rest_api_key}&redirect_uri={KAKAO_CALLBACK_URI}&response_type=code"
#     )
# def kakao_callback(request):
#     rest_api_key = getattr(settings, 'KAKAO_REST_API_KEY')
#     code = request.GET.get("code")
#     redirect_uri = KAKAO_CALLBACK_URI
#     """
#     Access Token Request
#     """
#     token_req = requests.get(
#         f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={rest_api_key}&redirect_uri={redirect_uri}&code={code}")
#     token_req_json = token_req.json()
#     error = token_req_json.get("error")
#     if error is not None:
#         raise JSONDecodeError(error)
#     access_token = token_req_json.get("access_token")
#     """
#     Email Request
#     """
#     profile_request = requests.get(
#         "https://kapi.kakao.com/v2/user/me", headers={"Authorization": f"Bearer {access_token}"})
#     profile_json = profile_request.json()
#     kakao_account = profile_json.get('kakao_account')
#     """
#     kakao_account에서 이메일 외에
#     카카오톡 프로필 이미지, 배경 이미지 url 가져올 수 있음
#     print(kakao_account) 참고
#     """
#     # print(kakao_account)
#     email = kakao_account.get('email')
#     """
#     Signup or Signin Request
#     """
#     try:
#         user = User.objects.get(email=email)
#         # 기존에 가입된 유저의 Provider가 kakao가 아니면 에러 발생, 맞으면 로그인
#         # 다른 SNS로 가입된 유저
#         social_user = SocialAccount.objects.get(user=user)
#         if social_user is None:
#             return JsonResponse({'err_msg': 'email exists but not social user'}, status=status.HTTP_400_BAD_REQUEST)
#         if social_user.provider != 'kakao':
#             return JsonResponse({'err_msg': 'no matching social type'}, status=status.HTTP_400_BAD_REQUEST)
#         # 기존에 Google로 가입된 유저
#         data = {'access_token': access_token, 'code': code}
#         accept = requests.post(
#             f"{BASE_URL}accounts/kakao/login/finish/", data=data)
#         accept_status = accept.status_code
#         if accept_status != 200:
#             return JsonResponse({'err_msg': 'failed to signin'}, status=accept_status)
#         accept_json = accept.json()
#         accept_json.pop('user', None)
#         return JsonResponse(accept_json)
#     except User.DoesNotExist:
#         # 기존에 가입된 유저가 없으면 새로 가입
#         data = {'access_token': access_token, 'code': code}
#         accept = requests.post(
#             f"{BASE_URL}accounts/kakao/login/finish/", data=data)
#         accept_status = accept.status_code
#         if accept_status != 200:
#             return JsonResponse({'err_msg': 'failed to signup'}, status=accept_status)
#         # user의 pk, email, first name, last name과 Access Token, Refresh token 가져옴
#         accept_json = accept.json()
#         accept_json.pop('user', None)
#         return JsonResponse(accept_json)
# class KakaoLogin(SocialLoginView):
#     adapter_class = kakao_view.KakaoOAuth2Adapter
#     client_class = OAuth2Client
#     callback_url = KAKAO_CALLBACK_URI

@api_view(['GET'])
@permission_classes([AllowAny, ])
def kakaoGetLogin(request):
    CLIENT_ID = SOCIAL_OUTH_CONFIG['KAKAO_REST_API_KEY']
    REDIRET_URL = SOCIAL_OUTH_CONFIG['KAKAO_REDIRECT_URI']
    url = "https://kauth.kakao.com/oauth/authorize?response_type=code&client_id={0}&redirect_uri={1}".format(
        CLIENT_ID, REDIRET_URL)
    res = redirect(url)
    return res

# @api_view(['GET'])
# @permission_classes([AllowAny, ])
# def getUserInfo(reqeust):
#     CODE = reqeust.query_params['code']
#     url = "https://kauth.kakao.com/oauth/token"
#     res = {
#             'grant_type': 'authorization_code',
#             'client_id': SOCIAL_OUTH_CONFIG['KAKAO_REST_API_KEY'],
#             'redirect_url': SOCIAL_OUTH_CONFIG['KAKAO_REDIRECT_URI'],
#             'client_secret': SOCIAL_OUTH_CONFIG['KAKAO_SECRET_KEY'],
#             'code': CODE
#         }
#     headers = {
#         'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'
#     }
#     response = requests.post(url, data=res, headers=headers)
#     # 그 이후 부분
#     tokenJson = response.json()
#     userUrl = "https://kapi.kakao.com/v2/user/me" # 유저 정보 조회하는 uri
#     auth = "Bearer "+tokenJson['access_token'] ## 'Bearer '여기에서 띄어쓰기 필수!!
#     HEADER = {
#         "Authorization": auth,
#         "Content-type": "application/x-www-form-urlencoded;charset=utf-8"
#     }
#     res = requests.get(userUrl, headers=HEADER)
#     return Response(res.text)

# def kakaoCallback(request):
#     return 
