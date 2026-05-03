import app

url = "https://google.com/"
seq = [[app.url_tokenizer.get(c, 1) for c in url]]
padded = app.pad_sequences(seq, maxlen=app.MAX_LEN, padding='post', truncating='post')
print(f"Padded shape: {padded.shape}")
pred = app.url_model.predict(padded, verbose=0)
print("Prediction Array:", pred)
import numpy as np
class_idx = int(np.argmax(pred[0]))
label = app.url_encoder.inverse_transform([class_idx])[0]
print("Label:", label)
