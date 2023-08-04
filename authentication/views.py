from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, send_mail
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from core import settings

from .tokens import generate_token


# Create your views here.
def home(request):
    return render(request, 'index.html')

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists! Please try another username.")
            return redirect('home')
        
        if len(username) > 20:
            messages.error(request, "Username must be under 20 charcters!")
            return redirect('home')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
            return redirect('home')
        
        
        if password1 != password2:
            messages.error(request, "Passwords don't matched!")
            return redirect('home')
        
        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('home')
        
        user = User.objects.create_user(username, email, password1)
        user.first_name = first_name
        user.last_name = last_name
        user.is_active = False
        user.save()
        messages.success(request, "Account created succesfully!! Please check your email to activate the account.")

        # The welcome email
        subject = "Welcome to Django Email Auth Testing"
        message = "Hello " + user.first_name + "!! \n" + "Welcome to Auth Testing!! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You" 
        from_email = settings.EMAIL_HOST_USER
        to_list = [user.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True) 

        # Confirmation email 
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ Django Auth!"
        message2 = render_to_string('email_confirmation.html',{
            'name': user.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [user.email]
        )
        send_mail(email_subject, message2, from_email, to_list, fail_silently=True)

        return redirect('signin')
    return render(request, 'signup.html')


    return render(request, 'signup.html')

def signin(request):
    return render(request, 'signin.html')

def activate(request):
    return render(request, 'activation_failed.html')

def logout(request):
    return render(request, 'logout.html')