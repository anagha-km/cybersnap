
from pathlib import Path
from background_detector import scan_background_leaks
import re

pattern = re.compile(
    r"\b(?:OTP|one[- ]time password|verification code|"
    r"security code)\s*[:#-]?\s*(?:is\s*)?(\d{4,8})\b",
    re.IGNORECASE,
)

text = "OTP: 123456"
match = pattern.search(text)

print("OTP test:", match.group(1) if match else "NOT DETECTED")
image_path = Path("test_screenshot.png")

result = scan_background_leaks(image_path)

print("CyberSnap Background Detector")
print("Total leaks detected:", result["leak_count"])

for finding in result["findings"]:
    print("Type:", finding["type"])
    print("Value:", finding["value"])
    print("Region:", finding["region"])
    test_values = [
    ("PAN", "ABCDE1234F"),
    ("Aadhaar", "2345 6789 0123"),
    ("Card", "4532 1234 5678 9012"),
    ("IPv4", "192.168.1.10"),
]

print("\nNew sensitive-data test values:")
for name, value in test_values:
    print(f"{name}: {value}")
