import requests
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import *
from .helpers import send_forget_password_mail
from django.urls import reverse
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

API_KEY = '0551f8ee3a17435da156e616badca87d' 

def get_news(request):
    query = request.GET.get('q')
    api_key = settings.NEWS_API_KEY

    url = f'https://newsapi.org/v2/everything?q={query}&apiKey={api_key}'
    response = requests.get(url)
    data = response.json()
    articles = data['articles']

    return JsonResponse({'articles': articles})



def HomePage(request):
    return render(request, 'home.html')


def Home2Page(request):
    return render(request, 'home2.html')


def SignupPage(request):
    

    if request.method=='POST':
        username=request.POST.get('username')
        email=request.POST.get('email')
        password1=request.POST.get('password1')
        password2=request.POST.get('password2')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists. Please choose a different username.")
            return redirect('signup')

        if password1!=password2:
          messages.error(request,"Your password and confirm password are not Same!!")
          return redirect('signup')
       
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Invalid email format. Please use a valid email address.")
            return redirect('signup')
        
        my_user = User.objects.create_user(username, email, password1)
        my_user.save()
        
         # Generate JWT token
        refresh = RefreshToken.for_user(my_user)
        token = str(refresh.access_token)
        
        
        
        return redirect('login')
    
    
    return render (request,'signup.html')


def LoginPage(request):
    if request.method=='POST':
        username=request.POST.get('username')
        password1=request.POST.get('password')
        user=authenticate(request,username=username,password=password1)
        if user is not None:
            login(request,user)
            
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            token = str(refresh.access_token)
            
            
            return redirect('home')
        else:
            error_message = "Username or password is incorrect!"
            return render (request,'login.html',{'error_message': error_message})

    return render (request,'login.html')

def LogoutPage(request):
    logout(request)
    return redirect('login')



@login_required(login_url='login')
def Home(request):
    return render(request,'home.html',{'title': 'Home Page'})



def ChangePassword(request , token=None):
    context = {}
    
    try:
        profile_obj = app1.objects.filter(forget_password_token=token).first()

        if not profile_obj:
            messages.error(request, 'Invalid reset link or link has expired.')
            return redirect(reverse('forget_password'))

        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return redirect(reverse('change_password', args=[token]))

            user_obj = profile_obj.user
            user_obj.set_password(new_password)
            user_obj.save()

            # Clear the forget password token
            profile_obj.forget_password_token = ''
            profile_obj.save()

            messages.success(request, 'Password has been successfully changed. You can now login with your new password.')
            return redirect('login')

               
    except Exception as e:
        print(e)
    return render(request, 'change-password.html', context)

import uuid


def ForgetPassword(request):
    try:
        if request.method == 'POST':
            username = request.POST.get('username')
            
            if not User.objects.filter(username=username).exists():
                messages.error(request, 'No user found with this username.')
                return redirect('/forget-password/')
            
            user_obj = User.objects.get(username = username)
            token = str(uuid.uuid4())
            app1_obj= app1.objects.get(user = user_obj)
            app1_obj.forget_password_token = token
            app1_obj.save()
            
            send_forget_password_mail(user_obj.email , token)
            messages.success(request, 'An email has been sent with a reset link.')
            return redirect('/forget-password/')
                
    
    
    except Exception as e:
        print(e)
    return render(request , 'forget-password.html', {'token': token})




    
    