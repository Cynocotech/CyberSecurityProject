import requests
import time

def test_url():
    print("Testing URL Prediction...")
    urls = ["https://google.com/", "http://bad-login-verify.xyz/login"]
    response = requests.post("http://localhost:5001/predict_url", json={"urls": urls})
    print(response.status_code, response.json())

def test_file():
    print("Testing File Prediction...")
    content = b"MZ\x00\x00\x00" + b"\x00" * 100 + b"payload execute shell"
    files = {'file': ('test.exe', content, 'application/octet-stream')}
    response = requests.post("http://localhost:5001/predict_file", files=files)
    print(response.status_code, response.json())

if __name__ == "__main__":
    test_url()
    test_file()
