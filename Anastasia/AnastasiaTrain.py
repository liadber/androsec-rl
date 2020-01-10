from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from joblib import dump, load
from Models.FeatureExtraction import get_intents_cmdcalls_apicalls
from Models.ClassifiersFunctions import train, model_accuracy
from Models.WriteFeatures import fill_list_of_features, create_bag_of_word, crate_train_test_csv_files


def feature_train(x_train, y_train):
    clf = ExtraTreesClassifier(n_estimators=600)
    clf = clf.fit(x_train, y_train)
    clf.feature_importances_
    dump(clf, 'AnastasiaFeaturesSelected.joblib')


def feature_selection(x):
    clf = load('AnastasiaFeaturesSelected.joblib')
    model = SelectFromModel(clf, prefit=True)
    x_new = model.transform(x)
    return x_new


def write_features_to_csv():
    X, Y = fill_list_of_features("../Files/benign/", "../Files/malware/", get_intents_cmdcalls_apicalls)
    X_bag = create_bag_of_word(X, "AnastasiaFeatures.joblib")
    feature_train(X_bag, Y)  # relevant only for Anstasia
    X_bag = feature_selection(X_bag)  # relevant only for Anstasia
    crate_train_test_csv_files(X_bag, Y)


def train_anastasia(train_file):#csv format
    clf = RandomForestClassifier(max_depth=8, n_estimators=600)#according to anastasia's article
    train(train_file, "AnastasiaClassifier.joblib", clf)


def model_accuracy_Anastasia(test_file):
    model_accuracy(test_file, "AnastasiaClassifier.joblib")


def main():
    write_features_to_csv()
    train_anastasia("Train.csv")
    model_accuracy_Anastasia("Test.csv")


if __name__ == '__main__':
    main()
