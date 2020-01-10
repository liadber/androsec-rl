from sklearn.feature_selection import SelectFromModel
from joblib import load
from Models.FeatureExtraction import get_intents_cmdcalls_apicalls


class AnastasiaDetector:
    def __init__(self):
        self.vectorizer = load("Anastasia/AnastasiaFeatures.joblib")
        self.feature_selector = load('Anastasia/AnastasiaFeaturesSelected.joblib')
        self.clf = load('Anastasia/AnastasiaClassifier.joblib')

    # this function return 1 if file is malware and 0 otherwise
    def detect(self, file):
        # feature extraction
        features = get_intents_cmdcalls_apicalls(file)
        # vectorize:
        X = self.vectorizer.transform([features]).toarray()
        # feature selection:
        model = SelectFromModel(self.feature_selector, prefit=True)
        X_new = model.transform(X)
        # predict:
        return int(self.clf.predict(X_new)[0])
