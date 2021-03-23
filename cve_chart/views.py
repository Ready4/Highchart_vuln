import json
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.shortcuts import render, redirect
from django.db.models import Count, Q
from .models import Vulnerability
from .forms import LoginForm, RegisterForm
# Create your views here.
User = get_user_model()

def register_view(request):
    form = RegisterForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data.get("username")
        email = form.cleaned_data.get("email")
        password = form.cleaned_data.get("password")
        try:
            user = User.objects.create_user(username, email, password)
        except:
            user = None
        if user != None:
            login(request, user)
            return redirect("/")
        else:
            request.session['register_error'] = 1
    return render(request, "registration.html", {"form":form})


def login_view(request):
    form = LoginForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data.get("username")
        password = form.cleaned_data.get("password")
        user = authenticate(request, username=username, password=password)
        if user != None:
            # request.user == user
            login(request, user)
            return redirect("/")
        else:
            request.session['invalid_user'] = 1
    return render(request, "login.html", {"form": form})

def logout_view(request):
    logout(request)
    # request.user anonim
    return redirect("/login")
#cvss<4 -> low severity
#4<=cvss<7 -> medium
#cvss>=7 -> high
@login_required(login_url='login')
def index(request):
    dataset = Vulnerability.objects \
        .values('cwe_code') \
        .annotate(low_count=Count('cwe_code', filter=Q(cvss__lte = 3.9)),
                medium_count=Count('cwe_code', filter=Q(cvss__gte = 4.0, cvss__lte = 6.9)),
                high_count=Count('cwe_code', filter=Q(cvss__gte =7))) \
                .order_by('cwe_code')

    categories = list()
    low_series = list()
    medium_series = list()
    high_series = list()

    for entry in dataset:
        categories.append('Cwe code %s' % entry['cwe_code'])
        low_series.append(entry['low_count'])
        medium_series.append(entry['medium_count'])
        high_series.append(entry['high_count'])

    return render(request, 'cwe_code.html', {
        'categories':json.dumps(categories),
        'low_series':json.dumps(low_series),
        'medium_series':json.dumps(medium_series),
        'high_series':json.dumps(high_series)
    })
