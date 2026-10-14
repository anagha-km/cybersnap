from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import json
from .models import ScanHistory


# Home page
@login_required
def home(request):
    return render(request, "home.html")


# Login
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        print("LOGIN USERNAME:", username)
        print("LOGIN PASSWORD:", password)

        user = authenticate(
            request,
            username=username,
            password=password
        )

        print("AUTH USER:", user)

        if user is not None:
            login(request, user)
            print("LOGIN SUCCESS")
            return redirect("home")

        print("LOGIN FAILED")

        return render(request, "login.html", {
            "error": "Invalid username or password."
        })

    return render(request, "login.html")


# Register
def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            return render(
                request,
                "register.html",
                {"error": "Passwords do not match"}
            )

        if User.objects.filter(username=username).exists():
            return render(
                request,
                "register.html",
                {"error": "Username already exists"}
            )

        User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        return redirect("login")

    return render(request, "register.html")


# Profile page
@login_required
def profile_view(request):
    return render(request, "profile.html")


# Logout
@login_required
def logout_view(request):
    logout(request)
    return redirect("login")


# Results page
@login_required
# Results page
@login_required
def results_view(request):
    if request.method == "POST":
        filename = request.POST.get("filename", "").strip()
        extracted_text = request.POST.get("extracted_text", "")
        detected_data = request.POST.get("detected_data", "[]")

        try:
            detected_data = json.loads(detected_data)
        except (json.JSONDecodeError, TypeError):
            detected_data = []

        if not filename:
            return render(request, "results.html", status=400)

        ScanHistory.objects.create(
            user=request.user,
            filename=filename,
            extracted_text=extracted_text,
            detected_data=detected_data
        )

        return render(request, "results.html")

    return render(request, "results.html")