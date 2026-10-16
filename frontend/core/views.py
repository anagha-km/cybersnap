
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
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is not None:
            login(request, user)
            return redirect("home")

        return render(request, "login.html", {
            "error": "Invalid username or password."
        })

    return render(request, "login.html")


# Register
def register(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")

        if not username or not password:
            return render(request, "register.html", {
                "error": "Username and password are required."
            })

        if password != confirm_password:
            return render(request, "register.html", {
                "error": "Passwords do not match."
            })

        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {
                "error": "Username already exists."
            })

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


# Results page and scan history saving
@login_required
def results_view(request):
    if request.method == "POST":
        filename = request.POST.get("filename", "").strip()
        protected_filename = request.POST.get(
            "protected_filename", ""
        ).strip()
        extracted_text = request.POST.get("extracted_text", "")
        detected_data_raw = request.POST.get("detected_data", "[]")

        try:
            detected_data = json.loads(detected_data_raw)
            if not isinstance(detected_data, list):
                detected_data = []
        except (json.JSONDecodeError, TypeError):
            detected_data = []

        if not filename:
            return render(request, "results.html", {
                "error": "No screenshot filename was received."
            }, status=400)

        ScanHistory.objects.create(
            user=request.user,
            filename=filename,
            protected_filename=protected_filename,
            extracted_text=extracted_text,
            detected_data=detected_data
        )

        history = ScanHistory.objects.filter(
            user=request.user
        ).order_by("-scan_date")

        return render(request, "results.html", {
            "filename": filename,
            "protected_filename": protected_filename,
            "extracted_text": extracted_text,
            "detected_data": detected_data,
            "history": history
        })

    history = ScanHistory.objects.filter(
        user=request.user
    ).order_by("-scan_date")

    return render(request, "results.html", {
        "history": history
    })


# History page
@login_required
def history_view(request):
    history = ScanHistory.objects.filter(
        user=request.user
    ).order_by("-scan_date")

    return render(request, "history.html", {
        "history": history
    })
