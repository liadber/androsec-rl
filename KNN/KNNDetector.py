from joblib import load
from Models.FeatureExtraction import get_permissions


class KNNDetector:
    def __init__(self):
        self.vectorizer = load("KNN/KNNFeatures.joblib")
        self.clf = load('KNN/KNNClassifier.joblib')


    #this function return 1 if file is malware and 0 otherwise
    def detect(self,file):
        # feature extraction
        features = get_permissions(file)
        # vectorize:
        X = self.vectorizer.transform([features]).toarray()
        # predict:
        return int(self.clf.predict(X)[0])
