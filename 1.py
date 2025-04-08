本人声明: 本人所发布的文章仅限用于学习和研究目的；不得将上述内容用于商业或者非法用途，否则，一切后果请用户自负。如有侵权请联系我删除处理。
"""
@Project: reptile_learning
@File: 1.py
@IDE: PyCharm
@Author: Pony.Bai
@Date: 2024/12/22 22:40
"""

import re
import time
import json
import random
import base64
import urllib3
import requests
from zlib import crc32
from base64 import b64encode
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Cipher import PKCS1_v1_5

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def AR_SHADOW_DES_encrypt(plaintext, key):
    key_bytes = key.encode("utf-8")
    plaintext_bytes = plaintext.encode("utf-8")
    padded_plaintext = pad(plaintext_bytes, DES.block_size)
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plaintext)
    return b64encode(ciphertext).decode("utf-8")


def AR_SHADOW_Base64Url(base64_string):
    if not base64_string:
        return ''
    base64number = base64_string.replace('+', '-')
    base64number = re.sub(r'/', '_', base64number)
    return base64number


def generate_random_string():
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    random_string = ''.join(random.choice(characters) for _ in range(8))
    return random_string


def get_crc_and_right_shift(data):
    encoded_s = data.encode()
    # 假设value是你要处理的数据
    bytes_value = encoded_s.to_bytes(4, 'little') if isinstance(encoded_s, int) else encoded_s
    crc = crc32(bytes_value)
    # 右移操作，Python中不需要手动做这个，因为crc32的结果已经是32位无符号整数
    shifted_crc = crc >> 0  # Python的位移操作自动忽略高位溢出
    return shifted_crc


def pad_start_zero(dec_number):
    return str(int(dec_number)).zfill(16)


def ar_show_doencypt(text):
    with open("rsa.public.pem") as f:
        public_key = f.read()
        # print("public_key:", public_key)
    # 基于公钥对数据加密（数据加密：公钥加密 数字签名：私钥加密）
    # 钥匙对象
    rsa_pk = RSA.importKey(public_key)
    # 基于公钥钥匙的算法对象
    rsa = PKCS1_v1_5.new(rsa_pk)
    encrypt_data = rsa.encrypt(text.encode())
    # (2) base64编码
    base64_encrypt_data = base64.b64encode(encrypt_data).decode()
    return base64_encrypt_data


def combined_str(key, num, stringpadding):
    combined_strs = f"{key}{num}|{stringpadding}|"
    return combined_strs


def com_str(str1, str2):
    string = "".join([str1, str2])
    return string


def encrypt_des(data, key):
    key_bytes = key.encode('utf-8')
    data_bytes = data.encode('utf-8')
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    padded_data = pad(data_bytes, 8)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data


def fet_ssign():
    datatims = str(int(time.time() * 1000))
    argument = {
        "0": f"1001035_{datatims}",
        "1": "W7ZEgfnv"
    }
    encrypted_data = encrypt_des(argument["0"], argument["1"])
    ssign = base64.b64encode(encrypted_data).decode('utf-8')
    return ssign


def get_queryparamid(datatims):
    datatims = str(int(time.time() * 1000))
    numberlist = f'0000000000000000000{datatims}||||3e37551033725f99e77bd868656e84b2|{datatims}||7$0.0.0.0$1$0$/regSch/deptSch$5oyJ5pel5pyf5oyC5Y+3$2$0$0$-$aHR0cHM6Ly9uZXRwaHNzei5laGVyZW4uY29t$false||7|1|0|||f51bb482c660d0eeadd1f058058a2b35|'
    key = generate_random_string()
    desbase64string02 = AR_SHADOW_DES_encrypt(numberlist, key)
    baselist02 = AR_SHADOW_Base64Url(desbase64string02)
    # print(baselist02)
    dec_number = len(baselist02)
    list = get_crc_and_right_shift(baselist02)
    stringpadding = pad_start_zero(list)
    # print(stringpadding)
    originaldata = combined_str(key, dec_number, stringpadding)
    # print(originaldata)
    base64string01 = ar_show_doencypt(originaldata)
    baselist01 = AR_SHADOW_Base64Url(base64string01)
    # print(baselist01)
    queryparamid = com_str(baselist01, baselist02)
    return queryparamid


def get_docSch(queryparamid, token):
    ssign = fet_ssign()
    headers = {
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "Origin": "https://h5.eheren.com",
        "Referer": "https://h5.eheren.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "accept": "*/*",
        "content-type": "application/json",
        "hrtoken": token,
        "phsid": "81681688",
        "phssign": ssign,
        "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\""
    }
    url = "https://szphs.eheren.com/regSch/docSch"
    params = {
        "arshadowurlqueryparamid": queryparamid
    }
    data = {
        "args": {
            "docId": "2030389",
            "docName": "管群",
            "docTitle": "主任医师",
            "docPhoto": "https://phsdevoss.eheren.com/pcloud/image/img-tx.png",
            "deptId": "1223",
            "deptName": "妇科",
            "hosId": "12675",
            "hosName": "江苏省中本部院区",
            "type": "order",
            "visitingArea": "",
            "clinicalType": "1",
            "source": 22,
            "sysCode": "1001035"
        },
        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    while True:
        response = requests.post(url, headers=headers, params=params, data=data, verify=False)
        data = response.json()
        return data


def Data_Processing(data, patientId):
    dataList = data['result']['dataList']
    # print(dataList)
    args = {
        "sysCode": "1001035",
        "ampm": "2",
        "categor": "18",
        "docId": "2031316",
        "deptId": "1240",
        "hosId": "12675",
        "schDate": "2024-12-27",
        "schId": "20210118000000000174",
        "enData": "sYGxZ/eQ7C3VQ1twfUv8OkESdGFgYz24VvxpkDbBtnsyS6U2pH5xljos08cT7rCA"

    }
    args02 = {
        "checkCode": "",
        "checkDate": "",
        "clinicalType": "1",
        "visitingArea": "",
        "ampm": "1",
        "appointmentNumber": "4",
        "categorName": "主任(西医)",
        "deptId": "1223",
        "deptName": "妇科",
        "docId": "2030389",
        "disNo": "4",
        "docName": "管群",
        "endTime": "",
        "extend": "",
        "fee": "35.00",
        "hosId": "12675",
        "hosName": "江苏省中本部院区",
        "isFlexible": "",
        "numId": "",
        "patientId": patientId,
        "resDate": "2025-01-02",
        "schId": "20201225000000000062",
        "source": 22,
        "startTime": "",
        "sysCode": "1001035",
        "thirdUserId": "",
        "timePoint": None,
        "schQukCategor": "妇科管群(正)",
        "commitOffset": 0
    }
    for schDateList_num in dataList:
        schDate = schDateList_num['schDate']
        schDateList = schDateList_num['schDateList']
        for ampmlist in schDateList:
            numRemain = ampmlist['numRemain']
            schId = ampmlist['schId']
            if int(numRemain) > 0 and schDate == '2025-01-02' and schId == "20201225000000000062":
                deptId = ampmlist['deptId']
                enData = ampmlist['enData']
                ampm = ampmlist['ampm']
                categor = ampmlist["categor"]
                categorName = ampmlist["categorName"]
                clinicalType = ampmlist["clinicalType"]
                docName = ampmlist["docName"]
                hosId = ampmlist["hosId"]
                schQukCategor = ampmlist["schQukCategor"]
                args.update({
                    "ampm": ampm,
                    "deptId": deptId,
                    "hosId": hosId,
                    "schDate": schDate,
                    "schId": schId,
                    "enData": enData
                })
                args02.update({
                    "clinicalType": clinicalType,
                    "ampm": ampm,
                    "categor": categor,
                    "categorName": categorName,
                    "deptId": deptId,
                    "resDate": schDate,
                    "schId": schId,
                    "docName": docName,
                    "schQukCategor": schQukCategor,

                })

    return args, args02


def get_numsource(queryparamid, args, token):
    ssign = fet_ssign()
    headers = {
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "Origin": "https://h5.eheren.com",
        "Referer": "https://h5.eheren.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "accept": "*/*",
        "content-type": "application/json",
        "hrtoken": token,
        "phsid": "81681688",
        "phssign": ssign,
        "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\""
    }
    url = "https://szphs.eheren.com/regSch/numSource"
    params = {
        "arshadowurlqueryparamid": queryparamid
    }
    data = {
        "args": args,

        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    response = requests.post(url, headers=headers, params=params, data=data, verify=False)
    preser = response.json()
    informantlist = preser['result']
    infornumber = {}
    for endatalist in informantlist:
        enData = endatalist['enData']
        timeDesc = endatalist['timeDesc']
        disNo = endatalist["disNo"]
        infornumber.update({
            "enData": enData,
            "timeDesc": timeDesc,
            "disNo": disNo
        })
    return infornumber


def get_mkapt(args01, args02, token):
    ssign = fet_ssign()
    args = {**args01, **args02}
    headers = {
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "Origin": "https://h5.eheren.com",
        "Referer": "https://h5.eheren.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "accept": "*/*",
        "content-type": "application/json",
        "hrtoken": token,
        "phsid": "81681688",
        "phssign": ssign,
        "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\""
    }
    url = "https://netphssz.eheren.com/phs-reg/regSch/mkApt"
    data = {
        "args": args,
        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    response = requests.post(url, headers=headers, data=data)
    return response.json()


def main(token, patientId):
    datatims = str(int(time.time() * 1000))
    queryparamid = get_queryparamid(datatims)
    data = get_docSch(queryparamid, token)
    args, args02 = Data_Processing(data, patientId)
    args01 = get_numsource(queryparamid, args, token)
    time.sleep(1)
    lastresult = get_mkapt(args01, args02, token)
    print(lastresult)


if __name__ == "__main__":
    token = "请输入你的token值"
    patientId = "请输入你的ID号码"
    main(token, patientId)
