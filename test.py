import traceback
import app

print('Testing URL model:')
try:
    app.safe_load_model('url_detection_model.h5')
except Exception as e:
    traceback.print_exc()

print('Testing File model:')
try:
    app.safe_load_model('malware_file_model.h5')
except Exception as e:
    traceback.print_exc()

print('Testing URL Pickle:')
try:
    app.load_pickle('url_tokenizer.pkl')
except Exception as e:
    traceback.print_exc()
print('Testing File Pickle:')
try:
    app.load_pickle('feature_scaler.pkl')
except Exception as e:
    traceback.print_exc()
