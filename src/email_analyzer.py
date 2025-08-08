import email
from email.header import decode_header
import re
import hashlib

URL_REGEX = r"(https?:\/\/[^\s'\"]+)"

def analyze_email_source(source):
    """Parses a raw email source and extracts key indicators.

    Args:
        source (str): The raw email source text.

    Returns:
        dict: A dictionary containing extracted URLs, sender info, etc.
    """
    msg = email.message_from_string(source)

    indicators = {
        "urls": set(),
        "sender": "",
        "subject": "",
        "attachment_hashes": [],
    }

    # Decode subject and sender
    subject, encoding = decode_header(msg["Subject"])[0]
    if isinstance(subject, bytes):
        subject = subject.decode(encoding or "utf-8")
    indicators["subject"] = subject

    sender, encoding = decode_header(msg["From"])[0]
    if isinstance(sender, bytes):
        sender = sender.decode(encoding or "utf-8")
    indicators["sender"] = sender

    # Walk through the email parts to find URLs
    for part in msg.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            body = part.get_payload(decode=True)
            try:
                body_text = body.decode()
                found_urls = re.findall(URL_REGEX, body_text)
                for url in found_urls:
                    indicators["urls"].add(url)
            except UnicodeDecodeError:
                continue # Ignore parts that can't be decoded

    # Extract attachment hashes
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
            continue

        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            if payload:
                sha256_hash = hashlib.sha256(payload).hexdigest()
                indicators["attachment_hashes"].append({
                    "filename": filename,
                    "sha256": sha256_hash
                })

    # Convert set to list for JSON serialization
    indicators["urls"] = list(indicators["urls"])

    return indicators
