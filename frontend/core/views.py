
import json

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import ScanHistory


# --------------------------------------------------
# Home page
# --------------------------------------------------
@login_required
def home(request):
    return render(request, "home.html")


# --------------------------------------------------
# Login
# --------------------------------------------------
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


# --------------------------------------------------
# Registration with password validation
# --------------------------------------------------
def register(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")

        # Check required fields
        if not username or not email or not password or not confirm_password:
            return render(request, "register.html", {
                "error": "All fields are required."
            })

        # Check password confirmation
        if password != confirm_password:
            return render(request, "register.html", {
                "error": "Passwords do not match."
            })

        # Check duplicate username
        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {
                "error": "Username already exists."
            })

        # Validate password
        try:
            validate_password(password)
        except ValidationError as errors:
            return render(request, "register.html", {
                "error": " ".join(errors.messages)
            })

        # Create user
        User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        return redirect("login")

    return render(request, "register.html")


# --------------------------------------------------
# Profile page
# --------------------------------------------------
@login_required
def profile_view(request):
    return render(request, "profile.html")


# --------------------------------------------------
# Logout
# --------------------------------------------------
@login_required
def logout_view(request):
    logout(request)
    return redirect("login")


# --------------------------------------------------
# Results page and scan-history saving
# --------------------------------------------------
@login_required
def results_view(request):

    # Save a newly completed scan
    if request.method == "POST":

        filename = request.POST.get(
            "filename", ""
        ).strip()

        protected_filename = request.POST.get(
            "protected_filename", ""
        ).strip()

        extracted_text = request.POST.get(
            "extracted_text", ""
        )

        detected_data_raw = request.POST.get(
            "detected_data", "{}"
        )

        risk_score_raw = request.POST.get(
            "risk_score", "0"
        ).strip()

        # Parse detected data
        try:
            detected_data = json.loads(detected_data_raw)

            if not isinstance(detected_data, (list, dict)):
                detected_data = {}

        except (json.JSONDecodeError, TypeError):
            detected_data = {}

        # Validate risk score
        # Accept integer or decimal values and restrict to 0-100.
        try:
            risk_score = int(float(risk_score_raw))
            risk_score = max(0, min(100, risk_score))

        except (ValueError, TypeError, OverflowError):
            risk_score = 0

        # Validate filename
        if not filename:
            return render(
                request,
                "results.html",
                {
                    "error": "No screenshot filename was received."
                },
                status=400
            )

        # Save the scan for the currently logged-in user
        scan = ScanHistory.objects.create(
            user=request.user,
            filename=filename,
            protected_filename=protected_filename,
            extracted_text=extracted_text,
            detected_data=detected_data,
            risk_score=risk_score
        )

        # Display the saved scan
        return render(
            request,
            "results.html",
            {
                "scan": scan,
                "filename": scan.filename,
                "protected_filename": scan.protected_filename,
                "extracted_text": scan.extracted_text,
                "detected_data": scan.detected_data,
                "risk_score": scan.risk_score,
            }
        )

    # GET request: display the most recent scan
    history = ScanHistory.objects.filter(
        user=request.user
    ).order_by("-scan_date")

    scan = history.first()

    if scan is None:
        return render(
            request,
            "results.html",
            {
                "history": history,
                "error": (
                    "No scan results found. "
                    "Please scan an image first."
                )
            }
        )

    return render(
        request,
        "results.html",
        {
            "scan": scan,
            "filename": scan.filename,
            "protected_filename": scan.protected_filename,
            "extracted_text": scan.extracted_text,
            "detected_data": scan.detected_data,
            "risk_score": scan.risk_score,
            "history": history,
        }
    )


# --------------------------------------------------
# Scan history with filename search
# --------------------------------------------------
@login_required
def history_view(request):
    search_query = request.GET.get("q", "").strip()

    my_scans = ScanHistory.objects.filter(
        user=request.user
    ).order_by("-scan_date")

    if search_query:
        my_scans = my_scans.filter(
            filename__icontains=search_query
        )

    return render(
        request,
        "history.html",
        {
            "history": my_scans,
            "search_query": search_query,
        }
    )


# --------------------------------------------------
# Upload view
# Screenshot analysis is handled by FastAPI.
# --------------------------------------------------
@login_required
def upload_view(request):

    if request.method == "POST":
        screenshot = request.FILES.get("screenshot")

        # Check whether a file was selected
        if not screenshot:
            return render(
                request,
                "home.html",
                {
                    "error": "Please select a screenshot."
                }
            )

        # Allow only supported image types
        allowed_types = [
            "image/png",
            "image/jpeg",
            "image/webp",
        ]

        if screenshot.content_type not in allowed_types:
            return render(
                request,
                "home.html",
                {
                    "error": (
                        "Please upload a PNG, JPG, or WEBP image."
                    )
                }
            )

        # Limit upload size to 10 MB
        if screenshot.size > 10 * 1024 * 1024:
            return render(
                request,
                "home.html",
                {
                    "error": "Image must be smaller than 10 MB."
                }
            )

        # Keep the existing JavaScript-to-FastAPI scanner flow
        return render(
            request,
            "home.html",
            {
                "error": (
                    "Please upload using the CyberSnap scanner "
                    "on this page."
                )
            }
        )

    return redirect("home")
