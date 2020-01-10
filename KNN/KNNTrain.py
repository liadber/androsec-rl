from sklearn.neighbors import KNeighborsClassifier
from Models.FeatureExtraction import get_permissions
from Models.WriteFeatures import write_features_to_csv
from Models.ClassifiersFunctions import train, model_accuracy



def write_features_to_csv_KNN():
    write_features_to_csv('../Files/benign/', '../Files/malware/', get_permissions, "KNNFeatures.joblib")


def train_KNN(train_file):#csv format
    neigh = KNeighborsClassifier(n_neighbors=3)
    train(train_file, "KNNClassifier.joblib", neigh)


def Model_Accuracy_KNN(test_file):
    model_accuracy(test_file, "KNNClassifier.joblib")


def main():
    write_features_to_csv_KNN()
    train_KNN("Train.csv")
    Model_Accuracy_KNN("Test.csv")


if __name__ == '__main__':
    main()

