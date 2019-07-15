import csv
import os
import sys
import glob
import InputLog
import pandas as pd
import unicodedata


EVENT_LOGIN = "4624"
EVENT_TGT = "4768"
EVENT_ST = "4769"
EVENT_PRIV = "4672"
EVENT_PROCESS = "4688"
EVENT_PRIV_SERVICE = "4673"
EVENT_PRIV_OPE = "4674"
EVENT_NTLM = "4776"
EVENT_SHARE = "5140"

RESULT_FILE='result.csv'
DOMAIN_NAME='example2.local'
TARGET_EVT=[EVENT_TGT,EVENT_ST,EVENT_PRIV,EVENT_PROCESS,
            EVENT_PRIV_SERVICE,EVENT_PRIV_OPE,EVENT_SHARE,EVENT_LOGIN,EVENT_NTLM]

write=None

label='normal'

df = pd.DataFrame(data=None, index=None,
                  columns=["eventid", "accountname", "clientaddr","id","date"], dtype=None, copy=False)

cnt=0
id=""

idlist=set()

def parse_event(org_row):
    global cnt,id,idlist
    #print(row)

    row = [i.strip('\t') for i in org_row]
    datetime = row[1]
    eventid = row[3]
    msg=row[5]
    item=msg.split("\n")
    org_accountname =""
    clientaddr=""
    sharedname=""
    servicename = ""
    processname = ""
    objectname = ""
    securityid=""
    if (eventid == EVENT_ST):
        cnt=cnt+1

    if (eventid in TARGET_EVT):

        item_account = [s for s in item if 'Account Name' in s]

        if len(item_account) == 0:
            item_account = [s for s in item if 'Logon Account' in s]

        org_accountname = item_account[0].split(":")[1]
        if eventid == EVENT_LOGIN:
            org_accountname = item_account[1].split(":")[1]

        item_clientaddr=""
        item_clientaddr = [s for s in item if 'Source Address' in s]
        if len(item_clientaddr) == 0:
            item_clientaddr = [s for s in item if 'Client Address' in s]
        if len(item_clientaddr) == 0:
            item_clientaddr = [s for s in item if 'Source Network Address' in s]
        if len(item_clientaddr) == 0:
            item_clientaddr = [s for s in item if 'Source Workstation' in s]
        if(len(item_clientaddr)>=1):
            clientaddrs=item_clientaddr[0].split(":")
            clientaddr = clientaddrs[len(clientaddrs)-1]

        item_service=""
        item_service = [s for s in item if 'Service Name' in s]
        if(len(item_service)>=2):
            servicename = item_service[0].split(":")[1]

        item_process = ""
        item_process = [s for s in item if 'Process Name' in s]
        if (len(item_process) >= 2):
            processname = item_process[0].split("New Process Name:")[1]
        elif (len(item_process) >=1):
            processname = item_process[0].split("Process Name:")[1]

        item_obj = ""
        item_obj = [s for s in item if 'Object Name' in s]
        if (len(item_obj) >= 2):
            objectname = item_obj[0].split(":")[1]

        item_id = ""
        item_id = [s for s in item if 'Security ID' in s]
        if (len(item_id) >= 2):
            securityid = item_id[0].split(":")[1]

        if (eventid==EVENT_SHARE):
            item_sharedname = [s for s in item if 'Share Name' in s]
            sharedname = item_sharedname[0].split(":")[1]

        datetime = datetime.strip("'")
        eventid = eventid.strip("'")
        if org_accountname != None:
            accountname = org_accountname.strip("'")
            accountname = accountname.lower()
            accountname = accountname.split('@')[0]
            if (accountname.find(DOMAIN_NAME)> -1 or len(accountname)==0):
                return
        if clientaddr != None:
            clientaddr = clientaddr.strip("'")
        if servicename != None:
            servicename = servicename.strip("'")
            servicename = servicename.lower()
        if processname != None:
            processname = processname.strip("'")
            processname = processname.lower()
        if objectname != None:
            objectname = objectname.strip("'")
            objectname = objectname.lower()
        if sharedname != None:
            sharedname = sharedname.strip("'")
            sharedname = sharedname.lower()
        id = ""
        id=(accountname+clientaddr+str(id)).strip()
        id=id.replace(" ","").replace("\t","")
        idlist.add(id)

        inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname, securityid)
        create_input_DL(inputLog)
    return

def parse_event_jp(org_row):
    global cnt,id,idlist
    #print(row)

    row = [i.strip('\t') for i in org_row]
    datetime = row[1]
    eventid = row[3]
    msg=row[5]
    item=msg.split("\n")
    org_accountname =""
    clientaddr=""
    sharedname=""
    servicename = ""
    processname = ""
    objectname = ""
    securityid=""
    if (eventid == EVENT_ST):
        cnt=cnt+1

    if (eventid in TARGET_EVT):

        item_account = [s for s in item if 'アカウント名' in s]

        if len(item_account) == 0:
            item_account = [s for s in item if 'ログオン アカウント' in s]

        org_accountname = item_account[0].split(":")[1]
        if eventid == EVENT_LOGIN:
            org_accountname = item_account[1].split(":")[1]

        item_clientaddr=""
        item_clientaddr = [s for s in item if 'ソース アドレス' in s]
        if len(item_clientaddr) == 0:
            item_clientaddr = [s for s in item if 'クライアント アドレス' in s]
        if len(item_clientaddr) == 0:
            item_clientaddr = [s for s in item if 'ソース ネットワーク アドレス' in s]
        if len(item_clientaddr) == 0:
            item_clientaddr = [s for s in item if 'ソース ワークステーション' in s]
        if(len(item_clientaddr)>=1):
            clientaddrs=item_clientaddr[0].split(":")
            clientaddr = clientaddrs[len(clientaddrs)-1]

        item_service=""
        item_service = [s for s in item if 'サービス名' in s]
        if(len(item_service)>=2):
            servicename = item_service[0].split(":")[1]

        item_process = ""
        item_process = [s for s in item if 'プロセス名' in s]
        if (len(item_process) >= 2):
            processname = item_process[0].split("新しいプロセス名:")[1]
        elif (len(item_process) >=1):
            processname = item_process[0].split("プロセス名:")[1]

        item_obj = ""
        item_obj = [s for s in item if 'オブジェクト名' in s]
        if (len(item_obj) >= 2):
            objectname = item_obj[0].split(":")[1]

        item_id = ""
        item_id = [s for s in item if 'セキュリティ IDD' in s]
        if (len(item_id) >= 2):
            securityid = item_id[0].split(":")[1]

        if (eventid==EVENT_SHARE):
            item_sharedname = [s for s in item if '共有名' in s]
            sharedname = item_sharedname[0].split(":")[1]

        datetime = datetime.strip("'")
        eventid = eventid.strip("'")
        if org_accountname != None:
            accountname = org_accountname.strip("'")
            accountname = accountname.lower()
            accountname = accountname.split('@')[0]
            if (accountname.find(DOMAIN_NAME)> -1 or len(accountname)==0):
                return
        if clientaddr != None:
            clientaddr = clientaddr.strip("'")
        if servicename != None:
            servicename = servicename.strip("'")
            servicename = servicename.lower()
        if processname != None:
            processname = processname.strip("'")
            processname = processname.lower()
        if objectname != None:
            objectname = objectname.strip("'")
            objectname = objectname.lower()
        if sharedname != None:
            sharedname = sharedname.strip("'")
            sharedname = sharedname.lower()
        id = ""
        id=(accountname+clientaddr+str(id)).strip()
        id=id.replace(" ","").replace("\t","")
        idlist.add(id)

        inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname, securityid)
        create_input_DL(inputLog)
    return

def create_input_DL(inputLog):
    global df,id
    eventid=inputLog.get_eventid()
    accountname=inputLog.get_accountname()
    clientaddr=inputLog.get_clientaddr()

    if not clientaddr:
        logs = df[(df.accountname == inputLog.get_accountname())
                                    & ((df.eventid == EVENT_ST) | (df.eventid == EVENT_LOGIN) |(df.eventid == EVENT_NTLM))
                                    ]
        latestlog = logs.tail(1)
        if (len(latestlog) > 0):
            clientaddr = latestlog.clientaddr.values[0]
            inputLog.set_clientaddr(clientaddr)

    series = pd.Series([eventid, accountname, clientaddr,id,inputLog.get_datetime()], index=df.columns)
    df = df.append(series, ignore_index=True)
    #writer.writerow([eventid, accountname, clientaddr])
    return

def greoup_event():
    global df,cnt, id,idlist,label

    f=open(RESULT_FILE, 'a')
    writer = csv.writer(f)
    writer.writerow(["date","eventid", "result","id"])

    for id in idlist:
        logs = df[(df.id == id)]
        #row=logs['eventid']
        events=""
        if(len(logs)>=2):
            for index, row in logs.iterrows():
                events=events+row['eventid']+" "
            if(len(events)>=1):
                writer.writerow([logs.date.tail(1),events,label,id])

def read_csv(inputdir):

    files = glob.glob(inputdir+"/*.csv")
    for file in files:
            with open(file, 'r') as f:
                row=''
                try:
                    reader = csv.reader(f)
                    header = next(reader)
                    ret = "﻿Keywords" in header[0]
                    print(header[0] + ","+str(ret))
                    rows = reversed(list(reader))
                    if (ret):
                        for row in rows:
                            if row:
                                parse_event(row)
                    else:
                        for row in rows:
                            if row:
                                parse_event_jp(row)
                except Exception as e:
                    print(file)
                    print(row)
                    #raise e
                finally:
                    f.close()

if __name__ == '__main__':
    if(os.path.isfile(RESULT_FILE)):
        os.remove(RESULT_FILE)
    if(len(sys.argv)>=3):
        label=sys.argv[2]
    read_csv(sys.argv[1])
    df = df.sort_index(ascending=False)
    greoup_event()