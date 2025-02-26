from fastapi import FastAPI, UploadFile
from parsers.metadata_extractor import extract_metadata
from parsers.body_analyzer import analyze_body
from parsers.attachment_analyzer import analyze_attachment

app = FastAPI()

@app.post("/analyze_email")
async def analyze_email(file: UploadFile):
    email_bytes = await file.read()
    
    metadata = extract_metadata(email_bytes)
    body = analyze_body(email_bytes.decode(errors="ignore"))
    
    return {"metadata": metadata, "body": body}