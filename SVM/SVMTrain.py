from sklearn.svm import SVC
from Models.FeatureExtraction import get_apicalls_and_permissions
from Models.WriteFeatures import write_features_to_csv
from Models.ClassifiersFunctions import train, model_accuracy

def write_features_to_csv_SVM():
    write_features_to_csv('../Files/benign/', '../Files/malware/', get_apicalls_and_permissions, "SVMFeatures.joblib")


def train_SVM(train_file):#csv format
    clf = SVC()
    train(train_file, "SVMClassifier.joblib", clf)


def Model_Accuracy_SVM(test_file):
    model_accuracy(test_file, "SVMClassifier.joblib")


def main():
    write_features_to_csv_SVM()
    train_SVM("Train.csv")
    Model_Accuracy_SVM("Test.csv")


if __name__ == '__main__':
    main()
