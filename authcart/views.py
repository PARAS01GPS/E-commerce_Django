from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from .utils import TokenGenerator,generate_token
from django.contrib.auth import authenticate,login,logout 
from django.core.mail import EmailMessage
from django.conf import settings
from django.utils.encoding import force_bytes, force_str,DjangoUnicodeDecodeError
from django.core import mail
from django.core.mail import send_mail,EmailMultiAlternatives
from django.core.mail import BadHeaderError,send_mail
from django.urls import NoReverseMatch,reverse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator


import threading

class EmailThread(threading.Thread):

    def __init__(self,email_message):
        self.email_message=email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()


def signup(request):
    if request.method=="POST":
        email=request.POST['email']
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        if password!=confirm_password:
            messages.warning(request,"Password is not Matching")
            return render(request,'signup.html')
        try:
            if User.objects.get(username=email):
                  
                messages.info(request,"Email is Taken")
                return render(request,'signup.html')
            
        except Exception as identifier:
            pass
        user = User.objects.create_user(email,email,password)
        user.is_active=False
        user.save()
        current_site=get_current_site(request)
        email_subject="Activate Your Account"
        message=render_to_string('activate.html',{
            'user':user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
        })

        email_message= EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
        # email_message.send( )
        EmailThread(email_message).start()
        messages.info(request,"Activate Your Account by clicking the link in your gmail")
        return redirect('/auth/login/')
  
    return render(request,"signup.html")


class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid= force_str(urlsafe_base64_decode(uidb64))
            user= User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/auth/login')
        return render(request,'activatefail.html')

def handlelogin(request):
    if request.method=="POST":

        username=request.POST['email']
        userpassword=request.POST['pass1']
        user=authenticate(username=username,password=userpassword)

        if user is not None:
            login(request,user)
            messages.success(request,"Login Success")
            # return render(request,'index.html')
            return redirect('/')
        
        else:
            messages.info(request,"Invalid Credentials")
            return redirect('/auth/login/')
    
    return render(request,'login.html')





class RequestResetEmailView(View):
    def get(self,request):
        return render(request,'reset.html')
    
    def post(self,request):
        email=request.POST['email']
        user= User.objects.filter(email=email)

        if user.exists():
            current_site=get_current_site(request)
            email_subject='[Reset Your Password]'
            messages=render_to_string('reset-password.html',{
            
                'domain':'127.0.0.1:8000',
                'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token':PasswordResetTokenGenerator().make_token(user[0])
            })


            email_message= EmailMessage(email_subject,messages,settings.EMAIL_HOST_USER,[email])
            EmailThread(email_message).start()
            
            return render(request,'reset.html')
        
class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id= force_str(urlsafe_base64_decode(uidb64))
            user= User.objects.get(pk=user_id)

            if  not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"Password Reset link is Invalid")
                return render(request,'reset.html')
        

        except DjangoUnicodeDecodeError as identifier:
            pass

        return render(request,'set-new-password.html',context)
    
    def post(self,request,uidb64,token):

        context={
            'uidb64':uidb64,
            'token':token
        }
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        if password!=confirm_password:
            messages.warning(request,"Password is not Matching")
            return render(request,'set-new-password.html',context)

        try:
            user_id= force_str(urlsafe_base64_decode(uidb64))
            user= User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request,"New Password Reset Successfully")
            return redirect('/auth/login/')
        
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,'Something went wrong')
        return render(request,'set-new-password.html',context)
        


def handlelogout(request):
    logout(request)
    messages.info(request,"Logout Successfully")
    return redirect('/auth/login')
        
        


