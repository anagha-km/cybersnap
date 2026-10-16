
from django.urls import path
from .views import home, login_view, register, logout_view, results_view, profile_view,history_view

urlpatterns = [
    path("register/", register, name="register"),
    path("login/", login_view, name="login"),
    path("", home, name="home"),
    path("home/", home, name="home_page"),
   path("results/", results_view, name="results"),
    path("history/", history_view, name="history"),
    path("profile/", profile_view, name="profile"),
    path("logout/", logout_view, name="logout"),
]