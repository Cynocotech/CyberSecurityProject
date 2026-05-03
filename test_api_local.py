import app
from flask import Flask

print('Testing URL_MODEL_OK:', app.URL_MODEL_OK)
print('Testing FILE_MODEL_OK:', app.FILE_MODEL_OK)

with app.app.test_client() as client:
    urls = ["https://google.com/", "http://bad-login-verify.xyz/login"]
    response = client.post('/predict_url', json={"urls": urls})
    print("URL Response:", response.get_json())
    
    content = b"MZ\x00\x00\x00" + b"\x00" * 100 + b"payload execute shell"
    files = {'file': ('test.exe', content, 'application/octet-stream')}
    response = client.post('/predict_file', data=files)
    print("File Response:", response.get_json())
