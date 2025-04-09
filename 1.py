# 本人声明: 本人所发布的文章仅限用于学习和研究目的；不得将上述内容用于商业或者非法用途，否则，一切后果请用户自负。如有侵权请联系我删除处理。

"""
@Project: reptile_learning
@File: ok.py
@IDE: PyCharm
@Author: Hacker
@Date: 2024/12/22 22:40
"""

# rsa.public.pem
# -----BEGIN PUBLIC KEY-----
# MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHalAfHNPkOqCvnmb9+cH2x8wI4
# 1MEWoWxe1UXu3ThL7JtxndmZZvuC3HWCl3vfQSVcgA0knchuPHx/6+hOv0/OiEPs4bJ0
# vNgDBkZisZ94MTkR3cbOJUVEEUY/wgBbrOU8d+mvYRSogZLuA4CA1KKqLEtmbXIiiYwv0
# nZW9knJwIDAQAB
# -----END PUBLIC KEY-----


import requests
import json
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import base64
import time

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from base64 import b64encode
import random
from zlib import crc32
import requests
import json
import base64
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import urllib3
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
    return  base64_encrypt_data
def combined_str(key,num,stringpadding):
    combined_strs = f"{key}{num}|{stringpadding}|"
    return combined_strs
def com_str(str1,str2):
    string="".join([str1, str2])
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
      "0":f"1001035_{datatims}",
      "1": "W7ZEgfnv"
    }
    encrypted_data = encrypt_des(argument["0"], argument["1"])
    ssign = base64.b64encode(encrypted_data).decode('utf-8')
    return ssign
def getdoctnum_args(docName,token):
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
    url = "https://netphssz.eheren.com/phs-reg/regDoc/searchDocAndDeptByWords"
    data = {
        "args": {
            "clinicalType": "1",
            "hosId": "12675",
            "searchContent": str(docName),
            "sysCode": "1001035"
        },
        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    response = requests.post(url, headers=headers, data=data)
    doct_list=response.json()
    # print(doct_list,type(doct_list))
    doct_args={}
    docInfoResultList=doct_list['result']['docInfoResultList'][0]
    deptName=docInfoResultList['deptName']
    docId=docInfoResultList['docId']
    deptId=docInfoResultList['deptId']
    docPhoto=docInfoResultList['docPhoto']
    docTitle=docInfoResultList['docTitle']
    hosName=docInfoResultList['hosName']
    hosId=docInfoResultList['hosId']
    doct_args.update({
            "docId": docId,
            "docName": str(docName),
            "docTitle": docTitle,
            "docPhoto":docPhoto,
            "deptId": deptId,
            "hosId":hosId,
            "hosName":hosName
    })
    return doct_args
def get_queryparamid():
    datatims = str(int(time.time() * 1000))
    numberlist = f'0000000000000000000{datatims}||||3e37551033725f99e77bd868656e84b2|{datatims}||7$0.0.0.0$1$0$/regSch/deptSch$5oyJ5pel5pyf5oyC5Y+3$2$0$0$-$aHR0cHM6Ly9uZXRwaHNzei5laGVyZW4uY29t$false||7|1|0|||f51bb482c660d0eeadd1f058058a2b35|'
    key=generate_random_string()
    desbase64string02 = AR_SHADOW_DES_encrypt(numberlist, key)
    baselist02 = AR_SHADOW_Base64Url(desbase64string02)
    # print(baselist02)
    dec_number = len(baselist02)
    list = get_crc_and_right_shift(baselist02)
    stringpadding = pad_start_zero(list)
    originaldata = combined_str(key, dec_number, stringpadding)
    base64string01 = ar_show_doencypt(originaldata)
    baselist01 = AR_SHADOW_Base64Url(base64string01)
    queryparamid = com_str(baselist01, baselist02)
    return queryparamid

def get_docSch(doct_args,queryparamid,token):
    args= {
        "type": "order",
        "visitingArea": "",
        "clinicalType": "1",
        "source": 22,
        "sysCode": "1001035"
    }
    args.update(doct_args)
    ssign=fet_ssign()
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
        "phssign":ssign,
        "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\""
    }
    url = "https://szphs.eheren.com/regSch/docSch"
    params = {
        "arshadowurlqueryparamid": queryparamid
    }
    data = {
        "args":args,
        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    while True:
        response = requests.post(url, headers=headers, params=params, data=data, verify=False)
        data = response.json()
        dataList = data['result']['dataList']

        return dataList
def Data_Processing(dataList):
    clinical_list = []
    clinical_list02 = []
    for schDateList_num in dataList:
        schDateList = schDateList_num['schDateList']
        for ampmlist in schDateList:
            args = {}
            args02 = {
                "checkCode": "",
                "checkDate": "",
                "visitingArea": "",
                "endTime": "",
                "extend": "",
                "hosId": "12675",
                "isFlexible": "",
                "numId": "",
                "source": 22,
                "startTime": "",
                "sysCode": "1001035",
                "thirdUserId": "",
                "timePoint": None,
                "commitOffset": 0
            }
            numRemain = ampmlist['numRemain']
            schDate=ampmlist['schDate']
            schId = ampmlist['schId']
            deptId = ampmlist['deptId']
            enData = ampmlist['enData']
            ampm = ampmlist['ampm']
            docId=ampmlist['docId']
            categorName = ampmlist["categorName"]
            clinicalType = ampmlist["clinicalType"]
            docName = ampmlist["docName"]
            deptName=ampmlist["deptName"]
            hosId = ampmlist["hosId"]
            schQukCategor = ampmlist["schQukCategor"]
            hosName=ampmlist["hosName"]
            fee=ampmlist["fee"]
            categor=ampmlist["categor"]
            # 这一句是条件语句，是可以修改的，建议根据是自己的实际情况选择时间
            if 0 < int(numRemain) < 40 and schDate=="2025-01-18":
                args.update({
                    "numRemain":numRemain,
                    "sysCode": "1001035",
                    "docId":docId,
                    "schDate": schDate,
                    "ampm": ampm,
                    "deptId": deptId,
                    "hosId": hosId,
                    "schId": schId,
                    "enData": enData,
                    "categor":categor
                })
                args02.update({
                    "clinicalType": clinicalType,
                    "ampm": ampm,
                    "categor": categor,
                    "categorName": categorName,
                    "deptId": deptId,
                    "resDate": schDate,
                    "schId": schId,
                    "docName":docName,
                    "schQukCategor":schQukCategor,
                    "fee":fee,
                    "deptName":deptName,
                    "hosName":hosName,
                    "docId":docId

                })
                clinical_list.append(args)
                clinical_list02.append(args02)
    return clinical_list[0],clinical_list02[0]
def get_patienId(token):
    ssign=fet_ssign()
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
        "hrtoken":token,
        "phsid": "81681688",
        "phssign": ssign,
        "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\""
    }
    url = "；"
    data = {
        "args": {
            "sysCode": "1001035"
        },
        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    response = requests.post(url, headers=headers, data=data)
    reslt=response.json()
    patienId=reslt['result'][0]['patienId']
    return patienId
def get_numsource(queryparamid,args,token):
    ssign=fet_ssign()
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
        "args":args,

        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    response = requests.post(url, headers=headers, params=params, data=data,verify=False)
    preser= response.json()
    # print(preser)
    informantlist=preser['result']
    # print(informantlist)
    infornumber_list=[]
    for endatalist in informantlist:
        infornumber = {}
        enData=endatalist['enData']
        timeDesc=endatalist['timeDesc']
        disNo=endatalist["disNo"]
        # 这个条件是自己加的额。。一定要加不然不能快速定位到票
        if timeDesc=='10:30-11:00':
            infornumber.update({
                      "enData": enData,
                      "timeDesc": timeDesc,
                      "disNo": disNo,
                      "appointmentNumber":disNo

                  })
            infornumber_list.append(infornumber)
    return infornumber_list[0]
def get_args(args01,args02):
    args = {**args01, **args02}
    return args

def get_mkapt(args,token,patienId):
    ssign = fet_ssign()
    args['patientId'] = patienId

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
        "args":args,
        "token": token
    }
    data = json.dumps(data, separators=(',', ':'))
    response = requests.post(url, headers=headers, data=data,verify=False)
    return response.json()

def main(token, docName):
      # 每个账户在注册或者登录_的时候，都会返回一个token值
      # docName就是医生的名字
      doct_args=getdoctnum_args(docName,token)
      # 第一步是得到医生的args一遍于第二步查询医生的坐班时间
      # print(doct_args)
      queryparamid = get_queryparamid()
      # print(queryparamid)
      # 医生值班请求发出前需要一个参数的破解
      dataList=get_docSch(doct_args,queryparamid,token)

      # 从而得到医生的坐班时间返回
      print(dataList)
      args,args02=Data_Processing(dataList)
      print(args,args02)
      # # 这一步也就是在为查票的余额和预定票做准备的参数环节有条件判断语句,
      # #  int(numRemain) > 0 and schDate == '2025-01-02' and schId == "20201225000000000062":
      # # # 判断哪一天的号码,是否有号源,上午还是下午,条件选择就在这一个函数里，，所以得看具体情况具体分析，可以在里面写条件，我先做一个大众版的
      # # 打印出所有有号的信息，将它们放进一个数组里供查阅，但是一般的抢票环节都是已经锁定了医生，几月几号，什么时间的，
      # # 所以可以在if条件里面加条件筛选出最终的抢票参数以便后面使用
      # 我选择了列表输出，然后从中选出第一个,也可以根据if判断直接定位就不用列表输出了
      args01=get_numsource(queryparamid,args,token)
      # print(args01)
      #
      # # # 在这一步我做了患者的信息提取一遍后续抢票使用

      patienId = get_patienId(token)
      args=get_args(args01,args02)

      time.sleep(3)

      lastresult=get_mkapt(args,token,patienId)
      print(lastresult)
if __name__ == "__main__":
    token =""
    docName= ""
    main(token, docName)
