import csv
import os
import sys
import glob

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

def preds(row):
    #print(row)

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
    if (eventid in TARGET_EVT):
        item_account = [s for s in item if 'Account Name' in s]
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
            clientaddr = item_clientaddr[0].split(":")[1]

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


    writer.writerow([datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname])

    return

def read_csv(inputdir):

    files = glob.glob(inputdir+"/*.csv")
    for file in files:
        #print(file)
        with open(file, 'r') as f:
            reader = csv.reader(f)
            header = next(reader)
            rows=reversed(list(reader))
            for row in rows:
                if row:
                    print(row)
                    preds(row)

if __name__ == '__main__':
    if(os.path.isfile(RESULT_FILE)):
        os.remove(RESULT_FILE)
    f=open(RESULT_FILE, 'a')
    writer = csv.writer(f)
    writer.writerow(
            ["datetime", "eventid", "accountname", "clientaddr", "servicename", "processname", "objectname", "sharedname"])
    read_csv(sys.argv[1])