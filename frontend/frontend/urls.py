"""
URL configuration for frontend project.
"""

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),

    # Favicon for the browser tab
    path(
        "favicon.ico",
        RedirectView.as_view(
            url="/static/core/favicon.ico",
            permanent=True,
        ),
    ),

    # Change password for logged-in users
    path(
        "password_change/",
        auth_views.PasswordChangeView.as_view(
            template_name="password_change.html",
            success_url="/password_change/done/",
        ),
        name="password_change",
    ),

    path(
        "password_change/done/",
        auth_views.PasswordChangeDoneView.as_view(
            template_name="password_change_done.html",
        ),
        name="password_change_done",
    ),
]

if settings.DEBUG:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT
    )
