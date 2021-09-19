# SZPT_ATLS

SZPT出校申请爬虫



## 安装

运行环境：[Python3](https://www.python.org/)

安装第三方库：`pip install -r requirements.txt`



## 使用教程

### config.ini

配置`config.ini`，配置用户名密码，邮箱提醒功能，以及出行路径。

配置完用户名密码就可以运行了

```
[user]
username = 19000000
password = password
```

```
[root@test]# python3 SZPT_ATLS.py 
[+] 登录成功
[+] 提交成功
```

如果需要启用邮箱提醒功能或修改出行路径，则需要继续配置对应信息。





#### 出行路径说明：

支持出行路径、出校理由修改。

```
[other]
#是否修改出行路径，true/false
#true会允许重复提交申请，而false一天只能提交一次
is_changePath = false
#如果为true，则按照下面的路径申请，false则自动爬取上一次的路径申请
MDDXXDZ = 目的地详细地址
CXJTFS = 出行交通方式
CXLY = 出校理由
```

- **支持出行路径修改，is_changePath默认值为false，会自动爬取上一次的路径进行申请。**
- **如果行程有变动，需要将is_changePath的值改为true，并修改出行路径、出现理由。**
- **日常行程没变动设置为false就好了**

**Example：**

```
[other]
is_changePath = true
MDDXXDZ = 西丽
CXJTFS = 步行
CXLY = 吃饭
```





### 自动申请

设置任务计划。如果不是服务器，也可以设置为开机自启动，详细可参考https://github.com/IamJankin/SZPT_Ehall



​	

## **注意：如果行程有变更，一定要修改出行路径。**

**如果行程有变更，一定要修改出行路径！一定要配合防疫工作！！！**
