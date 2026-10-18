from pathlib import Path
from background_detector import scan_background_leaks

image_path = Path("test_screenshot.png")

result = scan_background_leaks(image_path)

print("CyberSnap Background Detector")
print("Total leaks detected:", result["leak_count"])

for finding in result["findings"]:
    print("Type:", finding["type"])
    print("Value:", finding["value"])
    print("Region:", finding["region"])