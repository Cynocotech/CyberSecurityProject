import traceback
import app
import os
import tensorflow as tf

path = os.path.join(app.BASE, 'malware_file_model.h5')
print("Trying Try 1:")
try:
    model = tf.keras.models.load_model(path, compile=False)
    print("Success")
except Exception as e:
    traceback.print_exc()
