import app
from flask import Flask
import io
import time

print("="*50)
print("URL MODEL BIAS TEST")
print("="*50)

test_urls = {
    "Benign": [
        "https://www.google.com/",
        "https://github.com/",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://www.microsoft.com/",
        "https://apple.com"
    ],
    "Phishing": [
        "http://secure-update-paypal-verify.net/login",
        "http://chase-bank-secure-auth.com/",
        "http://verify-your-apple-id.xyz/",
        "http://amazon-support-help-desk.info"
    ],
    "Malicious": [
        "http://malware-download-domain.ru/payload.exe",
        "http://192.168.1.100:8080/shell.sh",
        "http://free-cracked-games-download.tk/crack.zip"
    ]
}

with app.app.test_client() as client:
    for category, urls in test_urls.items():
        print(f"\n--- Testing Expected {category} URLs ---")
        response = client.post('/predict_url', json={"urls": urls})
        results = response.get_json()['results']
        for r in results:
            print(f"URL: {r['url']}")
            print(f"Prediction: {r['result']} (Confidence: {r['confidence']}%)\n")


print("="*50)
print("FILE MODEL BIAS TEST")
print("="*50)

test_files = {
    "Benign Text": b"This is a normal text file with no malicious content.",
    "Benign PDF Header": b"%PDF-1.4\n" + b"A normal document content.",
    "Malicious MZ Payload": b"MZ\x00\x00\x00\x00\x00\x00\x00" + b"\x00"*200 + b"payload execute shell cmd powershell",
    "Malicious Script": b"import os; os.system('exec shell payload')"
}

with app.app.test_client() as client:
    for name, content in test_files.items():
        print(f"\n--- Testing {name} ---")
        files = {'file': (io.BytesIO(content), 'test.bin')}
        response = client.post('/predict_file', data=files, content_type='multipart/form-data')
        result = response.get_json()
        print(f"Prediction: {result.get('prediction')} (Confidence: {result.get('confidence')}%)\n")
