/*
 * @Author: Ending-Z 
 * @Date: 2017-09-07 10:30:06 
 * @Last Modified by:   Ending-Z 
 * @Last Modified time: 2017-09-07 10:30:06 
 */
from bs4 import BeautifulSoup as bs
import urllib.request
import re
import xlrd
import datetime
import requests
from lxml import etree
import time
#正常访问请求cookie值
def getcookie():
    url=r'http://www.cnnvd.org.cn/web/vulnerability/querylist.tag'
    header={}
    header['User-Agent']=r'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36'
    r = requests.get(url=url,headers=header)
    if r.status_code == 200:
        for cookie in r.cookies:
            a=str(cookie).split(' ')
    return a[1]

#获取表单CSRF值
def getCSRF(Cookie):
    url=r'http://www.cnnvd.org.cn/web/vulnerability/querylist.tag'
    header={}
    header['User-Agent']=r'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36'
    header['Cookie']=Cookie
    r = requests.get(url=url,headers=header)
    sel = etree.HTML(r.content)        
    CSRF=sel.xpath('//input[@name="CSRFToken"]/@value')
    CSRF=CSRF[0]
    return CSRF

#请求查询内容，设定http头，post表单，发送
def dosearch(CVE,CSRF,Cookie):
    header={}
    header['Host']=r'www.cnnvd.org.cn' 
    header['User-Agent']=r'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36'
    header['Accept']=r'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' 
    header['Accept-Language']=r'en-US,en;q=0.5' 
    header['Referer']=r'http://www.cnnvd.org.cn/web/vulnerability/querylist.tag' 
    header['Cookie']=Cookie
    header['Connection']=r'close' 
    header['Upgrade-Insecure-Requests']=r'1'
    header['Content-Type']=r'application/x-www-form-urlencoded' 


    data={}
    data['qcvCnnvdid']=CVE
    data['cvHazardRating']=''
    data['cvVultype']=''
    data['qstartdateXq']=''
    data['cvUsedStyle']=''
    data['cvCnnvdUpdatedateXq']=''
    data['cpvendor']=''
    data['relLdKey']=''
    data['hotLd']=''
    data['isArea']=''
    data['qcvCname']=''
    data['qstartdate']=''
    data['qenddate']=''
    data['CSRFToken']=CSRF
    url2=r'http://www.cnnvd.org.cn/web/vulnerability/queryLds.tag'
    data=urllib.parse.urlencode(data).encode('utf-8')

    #获取到查询界面，获取需要的URL
    r1=requests.post(url=url2,data=data,headers=header) 
    htmlcontent=r1.content.decode('utf-8') 
    herf=r'<a href="(.*)" target="_blank" class="a_title2" >'#/web/xxk/ldxqById.tag?CNNVD=CNNVD-201708-806
    herfurl=re.findall(herf,htmlcontent)
    print('查询url成功')
    time.sleep(0.1)
    #获取指定漏洞URL，get方式请求页面
    newurl=r'http://www.cnnvd.org.cn'+herfurl[0]
    head1={}
    head1['User-Agent']=r'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36'
    head1['Cookie']=Cookie
    result=requests.get(newurl,head1)
    resultcontent=result.content.decode('utf-8')
    print('查询成功')
    return resultcontent



def searchtitle(resultcontent):
#从返回页面查询所需数据
    title=r'<h2>(.*)</h2>'#Mozilla Firefox 安全漏洞
    title_r=re.findall(title,resultcontent)
    return title_r[0]


def searchrisk(resultcontent):
    risk=r'/web/images/jb_(.*).png'#高危
    risk_r=re.findall(risk,resultcontent)
    riskname=''
    if risk_r[0]=='0':
        riskname='无'
    elif risk_r[0]=='1':
        riskname='低危'
    elif risk_r[0]=='2':
        riskname='中危'
    elif risk_r[0]=='3':
        riskname='高危'
    elif risk_r[0]=='4':
        riskname='超危'
    return riskname

def searchsummary(resultcontent):
    #搜索漏洞简介	
    soupcontent=bs(resultcontent,"lxml")
    Summary=soupcontent.find_all(class_="d_ldjj")
    Summary=Summary[0]
    Summary=Summary.find_all(style="text-indent:2em")
    Summary_r=''
    for i in range(1,len(Summary)+1):
        Summary_r=Summary_r+Summary[i-1].string.strip()
    return Summary_r#summary

def searchsolution(resultcontent):
    #搜索解决方案
    soupcontent=bs(resultcontent,"lxml")
    solution=soupcontent.find_all(class_="d_ldjj m_t_20")
    solution=solution[0]
    solution=solution.find_all(style="text-indent:2em")
    solution_r=''
    for i in range(1,len(solution)+1):
        solution_r=solution_r+solution[i-1].string.strip()
    return solution_r

