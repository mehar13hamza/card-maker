from django.shortcuts import render, redirect, get_object_or_404
from django.http import StreamingHttpResponse
from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from .forms import CreateUserForm,UserProfileForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import  check_password, make_password
from django.contrib.auth import login as auth_login
from django.contrib import messages
from django.contrib.auth.decorators import login_required

# Create your views here.

def home(request):
    if request.method=="POST":
        request.session.flush()

        username = request.POST["username"]
        password = request.POST["password"]

        user = User.objects.filter(username__iexact=username).exists()

        if user:
            user = User.objects.filter(username__iexact = request.POST["username"])[0]
            if check_password(password,user.password):
                request.session['logged_in'] = {'username':user.username, 'id':user.id}

                return redirect('new')


        context = {

            'no_match':True
        }

        return render(request, 'colorful.html', context)


    return render(request, 'colorful.html')

def new(request):
    if 'logged_in' in request.session:
        return render(request, 'new.html')
    else:
        return redirect('signup')

def checkout(request):
    return render(request, 'checkout.html')


def signupUser(request):

    if 'logged_in' in request.session:
        return render(request, 'new.html')
    else:
        form = CreateUserForm()
        request.session.flush()
        if request.method == 'POST':
            user = {'username':request.POST['username'], 'email':request.POST['email'], 'password1':request.POST['password'], 'password2':request.POST['password']}
            print(user)
            form = CreateUserForm(user)
            if form.is_valid():
                form.save()
                user = User.objects.all().order_by('-id')[0]
                form = UserProfileForm({'address':request.POST['address'], 'DOB':request.POST['DOB'], 'user':user})
                if form.is_valid():
                    instance = form.save()
                    messages.success(request, 'Account was created for ' + user.username)
                    request.session['logged_in'] = {'username':user.username, 'id':user.id}
                    return redirect('home')
                else:
                    print(form.errors)

            else:
                print(form.errors)


        context = {'form':form}
        return render(request, 'signup.html', context)

def loginUser(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            request.session['logged_in'] = {'user_id':user.id}
            return redirect('new')
        else:
            messages.info(request, 'Username or Password is Incorrect')
            # return render(request, 'login.html', Context)

    Context = {}
    return redirect('home')


def logoutUser(request):
    logout(request)
    return redirect('home')