import email
from email import policy
from email.parser import BytesParser

def parse_email(email_bytes):
    """Parses raw email bytes and extracts structured information."""
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    
    return {
        "sender": msg["From"],
        "recipient": msg["To"],
        "cc": msg["Cc"],
        "subject": msg["Subject"],
        "timestamp": msg["Date"],
        "message_id": msg["Message-ID"],
        "headers": dict(msg.items()),
        "body": extract_body(msg),
        "attachments": extract_attachments(msg),
    }

def extract_body(msg):
    """Extracts the email body, handling plain text and HTML."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")

def extract_attachments(msg):
    """Extracts attachments, returning their filenames and MIME types."""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() != "multipart" and part.get("Content-Disposition"):
                attachments.append({
                    "filename": part.get_filename(),
                    "mime_type": part.get_content_type(),
                })
    return attachments