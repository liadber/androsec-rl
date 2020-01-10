import os
import pandas as pd
import numpy as np
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from sklearn import tree
from sklearn.externals import joblib
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score, train_test_split

n_gram_amount=300
def get_features(file):
    apk_file=apk.APK(file)
    bytes_3=get_dex_3byte_grams(apk_file)#dictionary of specific this apk file.
    return bytes_3

def feature_selection(features):
    to_write = ""
    for feature in features:
        to_write = to_write + feature + ","
    to_write = to_write[:len(to_write) - 1]
    file = open("features.txt", "w")
    file.write(to_write)
    file.close()

def get3chars_list(s):

    """
          Return list of all the 3-grams in s.

          :param s: a unicode string to split to 3 grams
          :type s: unicode string

          :rtype: a list of unicode strings.
              """
    trio_list = []
    for i in range(0, len(s) - 2):
        trio_list.append(s[i] + s[i + 1] + s[i + 2])
    return trio_list

def get_dex_3byte_grams(apk):
    """
           Return dictionary (key: 3-bytes-gram in dex of the given apk, value: this gram's frequency in dex of the given apk)

           :param apk: apk file
           :type apk: APK

           :rtype: a dictionary of {(key: unicode, value: int)
           """
    dex = dvm.DalvikVMFormat(apk.get_dex())
    dex_strings = dex.get_strings()
    trio_freq = {}  # key: trio, value: frequency
    remainder = u''
    for i in range(0, len(dex_strings)):
        trio_list = get3chars_list(remainder + dex_strings[i])
        remainder = dex_strings[i][-2:]
        for trio in trio_list:
            if trio_freq.get(trio) != None:
                trio_freq[trio] += 1
            else:
                trio_freq[trio] = 0
    return trio_freq

def max_trio_freq(trio_freq,amount):
    max_trio=[]
    for i in range(0, amount):
        max=0
        argmax=u''
        for trio in trio_freq:
            if trio_freq[trio]>max:
                max= trio_freq[trio]
                argmax=trio
        if argmax!=u'':
            max_trio.append(argmax)
            del trio_freq[argmax]
    return max_trio


def getSelectedFeatures(features, path_dict):
    features_Selected = []
    for f_path in path_dict:
        record = []
        for trio in features:
            if trio in path_dict[f_path]:
                record.append(1)
            else:
                record.append(0)
        features_Selected.append(record)
    return features_Selected



def train(train_file):#csv format
    data_train = np.genfromtxt(open(train_file, "r"), delimiter=",")
    y_train = data_train[:, 1][1:]
    X_train = data_train[:, 2:][1:]
    clf = tree.DecisionTreeClassifier()
    clf.fit(X_train, y_train)
    #write to file:
    joblib.dump(clf,'finalized_model.joblib')

def Model_Accuracy(test_file):
    clf = joblib.load('finalized_model.joblib')
    data_test = np.genfromtxt(open(test_file, "r"), delimiter=",")
    y_test = data_test[:, 1][1:]
    X_test = data_test[:, 2:][1:]
    #predict
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    scores = cross_val_score(clf, X_test, y_test, cv=3)  # todo: change when we get more files
    print("Accuracy:" + str(scores.mean()))

def main():
    trio_freq = {} #the whole dictionary of trio_frquency for all the files.
    path_dict={}
    Y=[]
    #add to Y and get features
    for file in os.listdir('../Files/benign'):
        try:
            apk_trio_freq= get_features('../Files/benign/'+file) #dictionary of specific this apk file.
            path_dict[file]=apk_trio_freq
            for key in apk_trio_freq:
                if key not in trio_freq:
                    trio_freq[key] = 0
                trio_freq[key] += apk_trio_freq[key]
            Y.append(0)  # not malware
        except:
            print("Problematic Mainfest: "+ file)
    for file in os.listdir('../Files/malware'):
        try:
            apk_trio_freq = get_features('../Files/malware/'+file)  # dictionary of specific this apk file.
            path_dict[file] = apk_trio_freq
            for key in apk_trio_freq:
                if key not in trio_freq:
                    trio_freq[key] = 0
                trio_freq[key] += apk_trio_freq[key]
            Y.append(1)  # malware
        except:
            print("Problematic Mainfest: " + file)
    #feature selection
    features=max_trio_freq(trio_freq,n_gram_amount)
    feature_selection(features)
    X=getSelectedFeatures(features,path_dict)
    print("X:",len(X))
    print("Y:",len(Y))
    #split to train and test
    X_train, X_test, y_train, y_test= train_test_split(X, Y, test_size=0.2, random_state=1)
    # write train:
    df_train = pd.DataFrame(X_train)
    df_train.insert(0, column='isMalware', value=y_train)
    df_train.to_csv("Train.csv")
    # write test:
    df_train = pd.DataFrame(X_test)
    df_train.insert(0, column='isMalware', value=y_test)
    df_train.to_csv("Test.csv")
    #train
    train("Train.csv")
    #test
    Model_Accuracy("Test.csv")


main()