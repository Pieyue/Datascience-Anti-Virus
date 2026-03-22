import os
import re
import pickle
import pefile
from joblib import Parallel, delayed

import elevate
from time import sleep
from datetime import datetime
from win10toast import ToastNotifier

TARGET_PATH = os.path.join(os.path.expanduser("~"), "Downloads")
with open('model.pkl', 'rb') as f:
    MODEL, HASHER = pickle.load(f)
if not os.path.exists('logs.csv'):
    with open('logs.csv', 'w', encoding='utf-8') as log:
        log.write('date,path,pred\n')

def get_pe_features(pe):
    pe_features = {}
    try:
        pe_features['num_sections'] = len(pe.sections)  # 节数量
        pe_features['image_base'] = pe.OPTIONAL_HEADER.ImageBase    # 程序加载到内存中的默认地址
        pe_features['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntrypoint
    except:
        pass
    return pe_features

def get_api_features(pe):
    api_dict = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for api in entry.imports:
                if api:
                    api_dict[api.name] = 1
    except:
        pass
    return api_dict

def get_features_wrappers(path):
    try:
        pe = pefile.PE(path, fast_load=True)
        pe_features = get_pe_features(pe)
        api_features = get_api_features(pe)
        pe.close()
    except:
        pe_features = {}
        api_features = {}
    string_features = get_string_features(path)
    wrappers = {**pe_features, **api_features, **string_features}
    return wrappers

def get_string_features(path):
    string_features = {}
    min_length = 5
    string_regx = b'[\x20-\x7E]{' + str(min_length).encode() + b',}'    # 匹配从空格到~的所有字符
    pattern = re.compile(string_regx)
    with open(path, 'rb') as f:
        strings = pattern.findall(f.read())

    for string in strings:
        string_features[string] = 1

    return string_features

def get_data(benign_path, malicious_path, hasher):
    def get_path(directory):
        return [os.path.join(directory, path) for path in os.listdir(directory)]
    all_paths = get_path(benign_path) + get_path(malicious_path)

    # 使用Parallel进行并行计算
    # delayed 创建任务
    raw_features_list = Parallel(n_jobs=-1)(
        delayed(get_features_wrappers)(path) for path in all_paths
    )

    X = hasher.transform(raw_features_list)
    y = [0] * len(os.listdir(benign_path)) + [1] * len(os.listdir(malicious_path))

    return X, y

def scan_engine(path):
    """ 杀毒引擎 """
    features = get_features_wrappers(path)
    features = HASHER.transform([features])
    pred = MODEL.predict(features)
    if pred == 0:
        pass
    else:
        os.system(f'del /F /Q {path}')
        alert(path)
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return pred, date

def write_logs(date, path, pred):
    with open('logs.csv', 'a', encoding='utf-8') as log:
        log.write(f'{date},{path},{pred}\n')

def alert(path):
    toaster = ToastNotifier()
    toaster.show_toast(
        title="发现病毒, 已成功删除",
        msg=f'位置 {path}',
        threaded=True
    )

if __name__ == '__main__':
    """ 伪·文件系统实时防御 """
    elevate.elevate()
    while True:
        exe_list = [os.path.join(TARGET_PATH, path) for path in os.listdir(TARGET_PATH) if path.endswith('.exe')]
        if exe_list:
            for exe in exe_list:
                pred, date = scan_engine(exe)
                write_logs(date, exe, pred)
        sleep(1)