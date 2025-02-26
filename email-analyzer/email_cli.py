import argparse
from parsers.metadata_extractor import extract_metadata
from parsers.body_analyzer import analyze_body
from parsers.attachment_analyzer import analyze_attachment

def analyze_email(file_path):
    """Extracts and analyzes an email file."""
    with open(file_path, "rb") as f:
        email_bytes = f.read()

    metadata = extract_metadata(email_bytes)
    body_analysis = analyze_body(email_bytes.decode(errors="ignore"))

    print("Metadata:", metadata)
    print("Body Analysis:", body_analysis)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze an email file")
    parser.add_argument("file", type=str, help="Path to the email file")
    args = parser.parse_args()

    analyze_email(args.file)