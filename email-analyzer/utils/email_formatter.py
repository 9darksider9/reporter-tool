import json

def format_email_data(parsed_email):
    """Formats parsed email data into a structured JSON output."""
    return json.dumps(parsed_email, indent=4, ensure_ascii=False)

def format_error_response(error_message):
    """Returns a standardized JSON error response."""
    return json.dumps({"error": error_message}, indent=4)