
from django.urls import path
from .views import (
    home,
    login_view,
    register,
    logout_view,
    results_view,
    profile_view,
    history_view,
    upload_view
)

urlpatterns = [
    path("", home, name="home"),
    path("home/", home, name="home_page"),
    path("login/", login_view, name="login"),
    path("register/", register, name="register"),
    path("logout/", logout_view, name="logout"),
    path("results/", results_view, name="results"),
    path("profile/", profile_view, name="profile"),
    path("history/", history_view, name="history"),
        path("upload/", upload_view, name="upload"),
]
