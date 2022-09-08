from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from . token import *
from django.http import HttpResponse,HttpResponseRedirect
from django.urls import reverse
import requests

# Create your views here.
def signin(request):
    if request.method=='POST':
        username=request.POST['username']
        password=request.POST['password']

        user = authenticate(request,username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('page')
        else:
            return redirect('signin')

    return render(request,'login.html')

def signup(request):
    if request.method=="POST":
        username=request.POST['username']
        pass1=request.POST['pass1']
        pass2=request.POST['pass2']
        email=request.POST['email']
        firstname=request.POST['fname']
        lastname=request.POST['lname']
        if User.objects.filter(username=username):
            print("this username is have")
            return redirect('signup')

        if len(pass1)<8:
            print("len is must more than 8 character")
            return redirect('signup')

        if pass1 != pass2:
            print("pass1 is not pass2")
            return redirect('signup')

        myuser=User.objects.create_user(username=username,email=email,password=pass1)
        myuser.first_name=firstname
        myuser.last_name=lastname
        myuser.is_active = False
        myuser.save()
        current_site = get_current_site(request)
        template=render_to_string('email.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        }
        )
        em=EmailMessage(
            'verification',
            template,
            settings.EMAIL_HOST_USER,
            [email]
        )
        em.fail_silenty=True
        em.send()
        return HttpResponseRedirect(reverse('signin'))
    return render(request,'signup.html')

def forgot(request):
    if request.method=='POST':
        username=request.POST['username']
        if User.objects.filter(username=username):
            user=User.objects.get(username=username)
            current_site = get_current_site(request)
            template=render_to_string('reset.html',{
            'name': user.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        }
        )
        em=EmailMessage(
            'verification',
            template,
            settings.EMAIL_HOST_USER,
            [user.email]
        )
        em.fail_silenty=True
        em.send()
        return HttpResponseRedirect(reverse('signin'))

    return render(request,'forgot.html')

def page(request):
    return render(request , '1.html')


def activate(request,uidb64,token):
    try:
        uid = force_bytes(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')


def reset_password(request,uidb64,token):
  
    try:
        uid = force_bytes(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        if request.method=='POST':
            print('kkkkk')
            user=request.POST['user']
            pass1=request.POST['pass1']
            pass2=request.POST['pass2']
            print(pass1)
            if pass1 !=pass2:
                print('the password shoud be the same')
            myuser.set_password(pass1)
            myuser.save()
            return redirect('signin')
        # user.profile.signup_confirmation = True
        print(uid)
        print(token)
        return render(request,'newpassword.html' , {'name':myuser.first_name ,'username' : myuser.username ,'token':token})
    else:
        return render(request,'activation_failed.html')

def newpassword(request,uidb64,token):
    if request.method=='POST':
        user=request.POST['user']
        pass1=request.POST['pass1']
        pass2=request.POST['pass2']
        print(pass1)
        if pass1 !=pass2:
            print('the password shoud be the same')
        myuser=User.objects.get(username=user)
        myuser.set_password(pass1)
        return redirect('signin')    
    return render(request,'newpassword.html')