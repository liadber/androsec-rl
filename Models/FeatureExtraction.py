from androguard.core.bytecodes.apk import *
from androguard.core.bytecodes import dvm


# this method receive apk file and extract only requested permissions in it's manifest
# returns the permissions as string
def get_permissions(apkFilePath):
    permissions = ""
    try:
        a = APK(apkFilePath)
        requested_permissions = a.get_permissions()
        for i in requested_permissions:
            permissions = permissions + " " + i
    except:
        return ""
    return permissions


def get_apicalls_and_permissions(file):
    try:
        features = ""
        a = APK(file)
        d = dvm.DalvikVMFormat(a. get_dex())
        z = d.get_strings()
        #api
        API_calls = ["getDeviceId","getCellLocation","setFlags","addFlags","setDataAndType","putExtra","init","query",
        "insert","update","writeBytes","write","append","indexOf","substring","startService","getFilesDir","openFileOutput","getApplicationInfo",
        "getRunningServices","getMemoryInfo","restartPackage","getInstalledPackages","sendTextMessage","getSubscriberId","getLine1Number","getSimSerialNumber","getNetworkOperator",
        "loadClass","loadLibrary","exec","getNetworkInfo","getExtraInfo","getTypeName","isConnected","getState","setWifiEnabled",
        "getWifiState","setRequestMethod","getInputStream","getOutputStream","sendMessage","obtainMessage","myPid","killProcess",
        "readLines","available","delete","exists","mkdir","ListFiles","getBytes","valueOf","replaceAll","schedule","cancel","read",
        "close","getNextEntry","closeEntry","getInstance","doFinal","DESKeySpec","getDocumentElement","getElementByTagName","getAttribute"]
        for i in range(len(z)):
            for j in range(len(API_calls)):
                if API_calls[j] == z[i]:
                    features = features + API_calls[j] + " "
        # permissions
        permissions = a.get_permissions()
        for p in permissions:
            features = features+p+" "
        return features
    except:
        return ""


def get_intents_cmdcalls_apicalls(file):
    try:
        features=""
        a = APK (file)
        d = dvm . DalvikVMFormat ( a. get_dex () )
        z = d . get_strings ()
        #intents
        for i in range ( len( z )):
            if z [i ]. startswith ( "android.intent.action."):
                intents = z[i ]
                features=features+ intents+" "
        #cmd
        suspicious_cmds = ["su", "mount", "reboot", "mkdir"]
        for i in range(len(z)):
            for j in range(len(suspicious_cmds)):
                if suspicious_cmds[j] == z[i]:
                    features=features+suspicious_cmds[j]+" "
        #api
        API_calls = ["getDeviceId","getCellLocation","setFlags","addFlags","setDataAndType","putExtra","init","query",
        "insert","update","writeBytes","write","append","indexOf","substring","startService","getFilesDir","openFileOutput","getApplicationInfo",
        "getRunningServices","getMemoryInfo","restartPackage","getInstalledPackages","sendTextMessage","getSubscriberId","getLine1Number","getSimSerialNumber","getNetworkOperator",
        "loadClass","loadLibrary","exec","getNetworkInfo","getExtraInfo","getTypeName","isConnected","getState","setWifiEnabled",
        "getWifiState","setRequestMethod","getInputStream","getOutputStream","sendMessage","obtainMessage","myPid","killProcess",
        "readLines","available","delete","exists","mkdir","ListFiles","getBytes","valueOf","replaceAll","schedule","cancel","read",
        "close","getNextEntry","closeEntry","getInstance","doFinal","DESKeySpec","getDocumentElement","getElementByTagName","getAttribute"]
        for i in range(len(z)):
            for j in range(len(API_calls)):
                if API_calls[j] == z[i]:
                    features = features + API_calls[j] + " "
        return features
    except:
        return ""
