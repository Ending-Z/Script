/*
 * @Author: Ending-Z 
 * @Date: 2017-09-07 10:30:21 
 * @Last Modified by:   Ending-Z 
 * @Last Modified time: 2017-09-07 10:30:21 
 */
# -*- coding: utf-8 -*-
import pandas as pd
from sqlalchemy import create_engine
import time
from test import *


Cookie=getcookie()
# result=pd.DataFrame(columns=['CVE','风险','Host','Protocol','Port','漏洞名称','漏洞简介','解决方案','Plugin Output'])
def gg(x):
    print('---------------------')   
    print(x)
    if x=='No':
        return 'Empty'
    else:
        try:
            global Cookie
            CSRF=getCSRF(Cookie)
            result=dosearch(x,CSRF,Cookie)
            return result
        except IndexError:
            print('超时失败')
            return 'Empty'


def n(x):
    if x=='Empty':
        return 'Empty'
    else:
        name=searchtitle(x)
        return name

def r(x):
    if x=='Empty':
        return 'Empty'
    else:
        risk=searchrisk(x)
        return risk

def s(x):
    if x=='Empty':
        return 'Empty'
    else:
        synopsis=searchsummary(x)
        return synopsis

def so(x):
    if x=='Empty':
        return 'Empty'
    else:
        solution=searchsolution(x)
        return solution


fileway=r'/Users/davidjun3/Desktop/'
f=fileway+'11.csv'
data=pd.read_csv(f)
df=data.drop(['Plugin ID','CVSS','Description','See Also'],1)
df=df[(True-df['Risk'].isin(['None']))]
df=df.fillna(value='No')



df['结果']=df['CVE'].apply(gg)
df['漏洞名称']=df['结果'].apply(n)
df['风险']=df['结果'].apply(r)
df['简介']=df['结果'].apply(s)
df['解决方案']=df['结果'].apply(so)

df=df.drop(['结果'],1)

df.to_csv(fileway+'canyin.csv',index=False,encoding='gb2312')






