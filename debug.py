import app
import numpy as np

print("Testing URL Model...")
try:
    url = "https://google.com/"
    seq = app.url_tokenizer.texts_to_sequences([url])
    padded = app.pad_sequences(seq, maxlen=app.MAX_LEN, padding='post', truncating='post')
    print("Padded shape:", padded.shape)
    prediction = app.url_model.predict(padded, verbose=0)
    print("Prediction:", prediction)
except Exception as e:
    import traceback
    traceback.print_exc()

print("Testing File Model...")
try:
    content = b"MZ\x00\x00\x00" + b"\x00" * 100 + b"payload execute shell"
    features, sha256 = app.extract_file_features(content)
    scaled = app.file_scaler.transform(features)
    print("Scaled input shape:", scaled.shape)
    prediction = app.file_model.predict(scaled, verbose=0)
    print("Prediction:", prediction)
except Exception as e:
    import traceback
    traceback.print_exc()
