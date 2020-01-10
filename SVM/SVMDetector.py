from joblib import load
from Models.FeatureExtraction import get_apicalls_and_permissions


class SVMDetector:
    def __init__(self):
        self.vectorizer = load("SVM/SVMFeatures.joblib")
        self.clf = load('SVM/SVMClassifier.joblib')

    # this function return 1 if file is malware and 0 otherwise
    def detect(self, file):
        # feature extraction
        features = get_apicalls_and_permissions(file)
        # vectorize:
        X = self.vectorizer.transform([features]).toarray()
        # predict:
        return int(self.clf.predict(X)[0])
