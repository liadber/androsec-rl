import os
from joblib import dump
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split


def write_features_to_csv(path_benign_dir, path_malware_dir, get_features_func, joblib_features_file):
    X, Y = fill_list_of_features(path_benign_dir, path_malware_dir, get_features_func)
    # get x to bag of words model:
    X_bag = create_bag_of_word(X, joblib_features_file)
    crate_train_test_csv_files(X_bag, Y)


def fill_list_of_features(path_benign_dir, path_malware_dir, get_features_func):
    X = []
    Y = []
    # bening:
    print("............................bening..............................")
    for file in os.listdir(path_benign_dir):
        features = get_features_func(path_benign_dir + file)
        if features != "":
            X.append(features)
            Y.append(0)  # not malware
    print("............................malware..............................")
    for file in os.listdir(path_malware_dir):
        features = get_features_func(path_malware_dir + file)
        if features != "":
            X.append(features)
            Y.append(1)  # malware
    return X, Y


def create_bag_of_word(X, joblib_features_file):
    # get x to bag of words model:
    vectorizer = CountVectorizer(analyzer="word", preprocessor=None, max_features=5000)
    X_bag = vectorizer.fit_transform(X)
    # write to file:
    dump(vectorizer, joblib_features_file)
    X_bag = X_bag.toarray()
    return X_bag


def crate_train_test_csv_files(X_bag, Y):
    # split to train and test
    X_train, X_test, y_train, y_test= train_test_split(X_bag, Y, test_size=0.2, random_state=1)
    # write to csv
    # write train:
    df_train = pd.DataFrame(X_train)
    df_train.insert(0, column='isMalware', value=y_train)
    df_train.to_csv("Train.csv")
    # write test:
    df_train = pd.DataFrame(X_test)
    df_train.insert(0, column='isMalware', value=y_test)
    df_train.to_csv("Test.csv")


