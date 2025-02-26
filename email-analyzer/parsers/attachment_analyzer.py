import hashlib
import magic

def hash_file(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def get_mime_type(file_bytes):
    mime = magic.Magic(mime=True)
    return mime.from_buffer(file_bytes)

def analyze_attachment(file_bytes, filename):
    return {
        "filename": filename,
        "mime_type": get_mime_type(file_bytes),
        "sha256": hash_file(file_bytes),
    }