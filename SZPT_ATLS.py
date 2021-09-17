import urllib.request, urllib.parse, urllib.error
import re
import http.cookiejar
from Crypto.Cipher import AES
import math
import random
import base64
import json
import sendMail
import time
import requests
import configparser
import os

#configparser初始化
dirname = os.path.split(os.path.realpath(__file__))[0]
config = configparser.ConfigParser()
config.read(dirname + "/config.ini", encoding="utf-8")
# 读取用户名密码
username = config.get("user", "username")
password = config.get("user", "password")

#URL
GET_INFO_POST_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/szptpubxsjkxxbs/mrxxbs/getSaveReportInfo.do'   #获取信息
GET_QueryUserTasks_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/emapflow/*default/index/queryUserTasks.do'
SAVE_INFO_POST_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/emapflow/tasks/startFlow.do'     #提交信息
#GET_SESSION_URL将返回一个包含随机sessionToken的登录页面
GET_SESSION_URL = 'https://ehall.szpt.edu.cn:443/amp-auth-adapter/login?service=https://ehall.szpt.edu.cn:443/publicappinternet/sys/szptpubxslscxbb/*default/index.do?nodeId=0&taskId=0&processInstanceId=0&instId=0&defId=0&defKey=0'
UPDATE_COOKIE_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/itpub/MobileCommon/getMenuInfo.do'
#LOGIN_URL = GET_LOGIN_URL()    #下面调用GET_LOGIN_URL()获取登录URL

# 请求头
header = {
    'User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Mobile Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Host': 'ehall.szpt.edu.cn',
}
header_getinfo = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Mobile Safari/537.36',

}

# 参数
APPID = ""
APPNAME = ""

lt = ''
execution = ''

# cookiejar
cookie = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie))

# AES
class AESCipher:

    def __init__(self, key):
        self.key = key[0:16].encode('utf-8')  # 只截取16位
        self.iv = self.random_string(16).encode()  # 16位字符，用来填充缺失内容，可固定值也可随机字符串，具体选择看需求。

    def __pad(self, text):
        """填充方式，加密内容必须为16字节的倍数，若不足则使用self.iv进行填充"""
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
        pad = ord(text[-1])
        return text[:-pad]

    def encrypt(self, text):
        """加密"""
        raw = self.random_string(64) + text
        raw = self.__pad(raw).encode()
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        """解密"""
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.__unpad(cipher.decrypt(enc).decode("utf-8"))

    @staticmethod
    def random_string(length):
        aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
        aes_chars_len = len(aes_chars)
        retStr = ''
        for i in range(0, length):
            retStr += aes_chars[math.floor(random.random() * aes_chars_len)]
        return retStr

# 密码AES加密
def pwdEncrypt(aes_key):
    pc = AESCipher(aes_key)
    password_aes = pc.encrypt(password)
    return password_aes

# 获取登录页面
def GET_LOGIN_URL():
    res = requests.get(GET_SESSION_URL, allow_redirects=False)
    LOGIN_URL = res.headers['Location']
    return LOGIN_URL
LOGIN_URL = GET_LOGIN_URL()


# 登录
def login():
    global APPID, APPNAME
    # 登录请求
    request = urllib.request.Request(url=LOGIN_URL,
                                     method='GET')
    response = opener.open(request)
    html = response.read().decode('utf-8')

    # 获取登录参数
    lt = re.search('name="lt" value="(.*?)"/>', html, re.S).group(1)
    execution = re.search('name="execution" value="(.*?)"/>', html, re.S).group(1)
    aes_key = re.search('pwdDefaultEncryptSalt = "(.*?)";', html, re.S).group(1)
    password_aes = pwdEncrypt(aes_key)
    # print(password_aes)
    params = {
        'username': username,
        'password': password_aes,
        'lt': lt,
        'dllt': 'userNamePasswordLogin',
        'execution': execution,
        '_eventId': 'submit',
        'rmShown': '1'
    }

    # 登录提交
    request = urllib.request.Request(url=LOGIN_URL, data=urllib.parse.urlencode(params).encode(encoding='UTF-8'), method='POST')
    response = opener.open(request)
    html = response.read().decode('utf-8')

    # 登录判断
    if "USERID='"+ username + "'" in html:
        APPID = re.search("APPID='(.*?)';", html, re.S).group(1)
        APPNAME = re.search("APPNAME='(.*?)';", html, re.S).group(1)
        return 0
    elif "您的用户名或密码有误，可尝试使用手机验证码登录" in html:
        return 1
    elif html.count("验证码") == 12:
        return 2
    else:
        return 3

# 设置cookies
def set_cookies():
    params_data = {}
    params_data["APPID"] = APPID
    params_data["APPNAME"] = APPNAME
    # 转换成json参数
    params = {
        'data': json.dumps(params_data)
    }
    # 更新Cookie: _WEU
    request = urllib.request.Request(url=UPDATE_COOKIE_URL,
                                     data=urllib.parse.urlencode(params).encode(encoding='UTF-8'),
                                     method='POST', headers=header) # 获取Cookie: _WEU
    opener.open(request)

def send_info():
    # 设置cookies
    set_cookies()

    # 获取个人信息json数据
    params = {
        'taskType': 'ALL_TASK',
        'nodeId': 'usertask1',
        'appName': 'szptpubxslscxbb',
        'module': 'modules',
        'page': 'apply',
        'action': 'getApplyData',
        '*order': '-CREATE_TIME',
        'pageNumber': 1,
        'pageSize': 10
    }
    request = urllib.request.Request(url=GET_QueryUserTasks_URL,
                                     data=urllib.parse.urlencode(params).encode(encoding='UTF-8'),
                                     method='POST', headers=header_getinfo)

    # 保存的参数
    response = opener.open(request)
    data1 = json.loads(response.read().decode('utf-8'))
    data1 = data1['datas']['queryUserTasks']['rows'][0]

    date = time.strftime("%Y-%m-%d", time.localtime())
    is_changePath = config.getboolean("other", "is_changePath")
    if(date == data1['REPORT_DATE'] and is_changePath == False):
        print('[-] 今日已经提交！')
    else:
        # 获取出校地址及交通工具
        data2_url = 'https://ehall.szpt.edu.cn/publicappinternet/sys/szptpubxslscxbb/modules/apply/T_IT_XSLSCXBB_CXLJ_QUERY.do?INFO_WID=%s'%data1['WID']
        request = urllib.request.Request(url=data2_url,method='POST', headers=header_getinfo)
        response = opener.open(request)
        data2 = json.loads(response.read().decode('utf-8'))
        data2 = data2['datas']['T_IT_XSLSCXBB_CXLJ_QUERY']['rows'][0]

        # 删除多余字段
        temp_dict = ['WID', 'OFFICE_MOBILE', 'SFZSWTGY', 'SFQWQTXQ', 'LXCXLJ', 'ZZCL', 'PROCESSINSTANCEID', 'DEFID',
                     'DEFKEY', 'FLOWSTATUS', 'FLOWSTATUSNAME', 'FLOWSUSPENSION', 'FLOWSUSPENSIONNAME', 'TASKINFO',
                     'NODEID', 'TASKID', 'NODENAME', 'TASKSTATUS', 'TASKSTATUSNAME', 'SFZSWTGY_DISPLAY',
                     'SFQWQTXQ_DISPLAY']
        for i in temp_dict:
            data1.pop(i)
        #构造要提交的数据包
        if is_changePath == True:#修改出校路径
            data1['cxljFormData'] = "[{\"MDDXXDZ\":\"%s\",\"CXJTFS\":\"%s\",\"SEQ\":%d}]" % (config.get("other", "MDDXXDZ"), config.get("other", "CXJTFS"), data2['SEQ'])
        else:
            data1['cxljFormData'] = "[{\"MDDXXDZ\":\"%s\",\"CXJTFS\":\"%s\",\"SEQ\":%d}]" % (data2['MDDXXDZ'], data2['CXJTFS'],data2['SEQ'])
        data1['ignoreSubTableModify'] = False
        data1['CREATE_TIME'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())     #创建时间
        data1['CXKSSJ'] = time.strftime("%Y-%m-%d 00:00:00", time.localtime())
        data1['CXJSSJ'] = time.strftime("%Y-%m-%d 23:59:00", time.localtime())
        data1['REPORT_DATE'] = time.strftime("%Y-%m-%d", time.localtime())

        params = {
            'formData':data1,
            'sendMessage':'true',
            'id':'start',
            'commandType':'start',
            'execute':'do_start',
            'name':'%E6%8F%90%E4%BA%A4',
            'url':'%2Fsys%2Femapflow%2Ftasks%2FstartFlow.do',
            'content':'%E6%8F%90%E4%BA%A4',
            'nextNodeId':'endevent1',
            'taskId':'',
            'defKey':'szptpubxslscxbb.szptpubxslscxbb'
        }
        request = urllib.request.Request(url=SAVE_INFO_POST_URL,
                                         data=urllib.parse.urlencode(params).encode(encoding='UTF-8'),
                                         method='POST', headers=header_getinfo)
        # 提交数据
        response = opener.open(request)
        try:
            # 判断是否提交成功
            result_json = json.loads(response.read().decode('utf-8'))
            if result_json["succeed"] == True:
                print("[+] 提交成功")
                sendMail.sendMail('SZPT - 提交成功 - 每日出校申请', "提交成功")
        except:
            print('[-] 需手动更新表单，以往表单数据不可用')
            sendMail.sendMail('SZPT - 需手动更新表单 - 每日出校申请',"需手动更新表单，以往表单数据不可用")

def main():
    login_status = login()
    if login_status == 0:
        print('[+] 登录成功')
        send_info()
    elif login_status == 1:
        print("[-] 登录失败，您的用户名或密码有误")
        sendMail.sendMail('SZPT - 用户名密码错误 - 每日出校申请',"您的用户名或密码有误")
    elif login_status == 2:
        print("[-] 无法登录，需要验证码，请稍后再试或手动填报。")
        sendMail.sendMail('SZPT - 无法登录，需要验证码 - 每日出校申请',"无法登录，需要验证码，请稍后再试或手动填报。")

    else:
        print("[-] 无法登录，未知错误，请检查网站是否能访问。")
        sendMail.sendMail('SZPT - 无法登录 - 每日出校申请',"无法登录，未知错误，请检查网站是否能访问")

if __name__ == '__main__':
    main()