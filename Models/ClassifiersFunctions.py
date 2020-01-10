from joblib import load, dump
import numpy as np
from sklearn . metrics import classification_report
from sklearn.model_selection import cross_val_score


def train(train_file, joblib_classifier_file, classifier):
    data_train = np.genfromtxt(open(train_file, "r"), delimiter=",")
    y_train = data_train[:, 1][1:]
    x_train = data_train[:, 2:][1:]
    classifier.fit(x_train, y_train)
    # write to file:
    dump(classifier, joblib_classifier_file)


def model_accuracy(test_file, joblib_classifier_file):
    classifier = load(joblib_classifier_file)
    data_test = np.genfromtxt(open(test_file, "r"), delimiter=",")
    y_test = data_test[:, 1][1:]
    x_test = data_test[:, 2:][1:]
    # predict
    y_pred = classifier.predict(x_test)
    print(classification_report(y_test, y_pred))
    scores = cross_val_score(classifier, x_test, y_test, cv=3)  # todo: change when we get more files
    print("Accuracy:" + str(scores.mean()))
