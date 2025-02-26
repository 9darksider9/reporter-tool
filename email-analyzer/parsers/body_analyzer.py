import base64
import re

def detect_base64(encoded_text):
    try:
        decoded = base64.b64decode(encoded_text).decode()
        return decoded if decoded.isprintable() else None
    except Exception:
        return None

def detect_obfuscation(html_body):
    js_patterns = [
        r"<script>.*?</script>",
        r"document.write\(",
        r"eval\(",
    ]
    return any(re.search(p, html_body, re.IGNORECASE) for p in js_patterns)

def analyze_body(email_body):
    return {
        "decoded_base64": detect_base64(email_body),
        "contains_obfuscation": detect_obfuscation(email_body),
    }