import email
import dkim
import spf
from email import policy
from email.parser import BytesParser

def extract_metadata(email_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    
    metadata = {
        "sender": msg["From"],
        "recipient": msg["To"],
        "cc": msg["Cc"],
        "subject": msg["Subject"],
        "timestamp": msg["Date"],
        "message_id": msg["Message-ID"],
    }

    # Extract SPF/DKIM/DMARC results (mock function)
    metadata["SPF"] = check_spf(msg)
    metadata["DKIM"] = check_dkim(msg)
    metadata["DMARC"] = check_dmarc(msg)

    return metadata