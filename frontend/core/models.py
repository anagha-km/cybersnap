
from django.db import models
from django.contrib.auth.models import User


class ScanHistory(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="scan_history"
    )

    filename = models.CharField(max_length=255)

    detected_data = models.JSONField(
        default=dict,
        blank=True
    )

    risk_score = models.IntegerField(default=0)

    protected_filename = models.CharField(
        max_length=255,
        blank=True,
        default=""
    )

    extracted_text = models.TextField(
        blank=True,
        default=""
    )

    scan_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.filename}"

    class Meta:
        ordering = ["-scan_date"]
