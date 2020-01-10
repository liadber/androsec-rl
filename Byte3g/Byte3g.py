import csv

from androguard.core.bytecodes import apk, dvm
from sklearn.externals import joblib
import numpy as np

class Byte3gDetector:
    def __init__(self):
        self.loaded_model = joblib.load('Byte3g/finalized_model.joblib')
        file = open("Byte3g/features.txt", "r")
        features_read=file.read()
        self.features=features_read.split(",")


    def __get3chars_list(self,s):
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

    def __get_dex_3byte_grams(self,apk):
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
            trio_list = self.__get3chars_list(remainder + dex_strings[i])
            remainder = dex_strings[i][-2:]
            for trio in trio_list:
                if trio_freq.get(trio) != None:
                    trio_freq[trio] += 1
                else:
                    trio_freq[trio] = 0
        return trio_freq

    def feature_extrtaction(self,f_path):
        apk_trio_freq = self.__get_dex_3byte_grams(apk.APK(f_path))  # dictionary of specific this apk file.
        features_extracted = []
        for feature in self.features:
            if feature in apk_trio_freq:
                features_extracted.append(1)
            else:
                features_extracted.append(0)
        return features_extracted

    def detect(self,file):
        features=self.feature_extrtaction(file)
        return int(self.loaded_model.predict([features])[0])

