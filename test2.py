import traceback
import sys
import os

BASE = os.path.join(os.path.dirname(__file__), 'backend')

def test_load(filename):
    path = os.path.join(BASE, filename)
    import tensorflow as tf
    try:
        model = tf.keras.models.load_model(path, compile=False)
        print("Success for", filename)
    except Exception as e:
        print("Failed Try 1 for", filename)
        traceback.print_exc()

test_load('url_detection_model.h5')
test_load('url_detection_model.keras')
test_load('malware_file_model.h5')
