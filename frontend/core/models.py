from django.db import models
from django.contrib.auth.models import User


class ScanHistory(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )
    filename = models.CharField(max_length=255)

    # Add this field
    protected_filename = models.CharField(
        max_length=255,
        blank=True,
        default=""
    )

    extracted_text = models.TextField(blank=True)
    detected_data = models.JSONField(default=list, blank=True)
    scan_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.filename}"