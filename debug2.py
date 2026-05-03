import app
import traceback

print("=== URL PRED ===")
try:
    url = "https://google.com/"
    seq = app.url_tokenizer.texts_to_sequences([url])
    padded = app.pad_sequences(seq, maxlen=app.MAX_LEN, padding='post', truncating='post')
    prediction = app.url_model.predict(padded, verbose=0)
    print("URL Pred Success:", prediction)
except Exception as e:
    traceback.print_exc()

print("=== FILE PRED ===")
try:
    content = b"MZ\x00\x00\x00" + b"\x00" * 100 + b"payload execute shell"
    features, sha256 = app.extract_file_features(content)
    scaled = app.file_scaler.transform(features)
    prediction = app.file_model.predict(scaled, verbose=0)
    print("File Pred Success:", prediction)
except Exception as e:
    traceback.print_exc()
