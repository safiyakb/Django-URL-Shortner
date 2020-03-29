from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from shorturl.models import UrlTable
import hashlib
# Create your views here.

def home(request):
    return render(request,"home.html")

def createHash(key):
    hash = hashlib.md5(key)
    return hash.hexdigest()[:5]

def signup(request):
	if request.method == "POST":
		username = request.POST.get("username")
		password = request.POST.get("password")
		email = request.POST.get("email")

		user = User.objects.create_user(
				username=username,
				password=password,
				email=email
			)
		login(request, user)

		return redirect("/dashboard/")

	return render(request, "signup.html")

def signin(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(username=username, password=password)
        if user != None:
            login(request, user)
            return redirect("/dashboard/")
    return render(request,"signin.html")

def dashboard(request):
    user = request.user
    url_instance = UrlTable.objects.filter(user=user)
    return render(request,"dashboard.html",{"url_instance":url_instance})

def create_short_url(request):
    if request.method == "POST":
        title = request.POST.get("title")
        long_url = request.POST.get("long_url")
        short_hash = createHash(long_url.encode())
        user = request.user
        
        url = UrlTable.objects.create(
            title = title,
            long_url=long_url,
            short_hash = short_hash,
            user = user  
        )
        return redirect("/dashboard/")

def redirect_to_long_url(request, hashcode):
    url = UrlTable.objects.get(short_hash=hashcode)
    long_url = url.long_url
    url.no_clicks += 1
    url.save()
    return redirect(long_url)

def signout(request):
    logout(request)
    return redirect("/signin/")


