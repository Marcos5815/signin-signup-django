from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.core.validators import validate_email
from django.contrib.auth.models import User

# Create your views here.
def signup(request):
    if request.method != 'POST':
        return render(request, 'accounts/signup.html')
    
    firstname = request.POST.get('firstname')
    lastname = request.POST.get('lastname')
    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    password2 = request.POST.get('password2')
    
    if not firstname or not lastname or not username or not email or not password or not password2:
        messages.error(request, 'No field can be empty.')
        return render(request, 'accounts/signup.html')
    
    try:
        validate_email(email)
        
    except:
        messages.error(request, 'Invalid e-mail')
        return render(request, 'accounts/signup.html')
    
    if len(password) < 6:
        messages.error(request, 'Password must be longer than 6 characters')
        return render(request, 'accounts/signup.html')
        
    if len(username) < 6:
        messages.error(request, 'Username must be longer than 6 characteres')
        return render(request, 'accounts/signup.html')
        
    if password != password2:
        messages.error(request, 'Passwords are not the same')
        return render(request, 'accounts/signup.html')
        
    if User.objects.filter(username=username).exists():
        messages.error(request, 'Username already exists')
        return render(request, 'accounts/signup.html')
        
    if User.objects.filter(email=email).exists():
        messages.error(request, 'E-mail already exists')
        return render(request, 'accounts/signup.html')
    
    messages.success(request, 'Registered')
    
    user = User.objects.create_user(first_name = firstname, last_name = lastname, email = email,
                                    username = username ,password = password)  
    
    return redirect('/')     

def signin(request):
    if request.method != 'POST':
        return render(request, 'accounts/signin.html')
    
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    user = auth.authenticate(request, username=username, password=password)
    
    if not user:
        messages.error(request, 'username or password is incorrect')
        return render(request, 'accounts/signin.html')
    else:
        auth.login(request, user)
        return redirect('dashboard')

def logout(request):
    auth.logout(request)
    return redirect('/')

@login_required(redirect_field_name="/")
def dashboard(request):
    return render(request, 'accounts/dashboard.html')