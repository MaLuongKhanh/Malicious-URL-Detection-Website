# Purpose - Receive the call for testing a page from the Chrome extension and return the result (SAFE/PHISHING)
# for display. This file calls all the different components of the project (The ML model, features_extraction) and
# consolidates the result.

import joblib
import features_extraction
import sys
import numpy as np

from features_extraction import LOCALHOST_PATH, DIRECTORY_NAME


def get_prediction_from_url(url, features=None):
    try:
        if features is None:
            features = features_extraction.main(url)
        
        # Load model với phiên bản scikit-learn mới
        clf = joblib.load('classifier/best_model.pkl')
        
        # Reshape features để phù hợp với input của model
        features = np.array(features, dtype=float).reshape(1, -1)
        
        pred = clf.predict(features)
        return int(pred[0])
        
    except Exception as e:
        print(f"Error in prediction: {str(e)}")
        return None


def main():
    url = sys.argv[1]

    prediction = get_prediction_from_url(url)

    # Print the probability of prediction (if needed)
    # prob = clf.predict_proba(features_test)
    # print 'Features=', features_test, 'The predicted probability is - ', prob, 'The predicted label is - ', pred
    #    print "The probability of this site being a phishing website is ", features_test[0]*100, "%"

    if prediction == 1:
        # print "The website is safe to browse"
        print("SAFE")
    elif prediction == -1:
        # print "The website has phishing features. DO NOT VISIT!"
        print("PHISHING")

        # print 'Error -', features_test


if __name__ == "__main__":
    main()
