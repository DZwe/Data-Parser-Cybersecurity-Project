import sys, re,  os
from subprocess import call
import moment
from datetime import datetime
import subprocess
import socket, struct
import MySQLdb

db = MySQLdb.connect(host="localhost",
                     user="root",
                     db="logs_db")
cur = db.cursor()

def parse(filePath):

    # Filter the given notice

    ip = []
    port = []
    dest_ip = []
    dest_port = []
    timestamp = []

    with open(filePath) as f:

        for line in f:
            ip.extend(re.findall(r"<IP_Address>(.*?)</IP_Address>", line))
            port.extend(re.findall(r"<Port>(.*?)</Port>", line))
            dest_ip.extend(re.findall(r"<dest_ip>(.*?)</dest_ip>", line))
            dest_port.extend(re.findall(r"<dest_port>(.*?)</dest_port>", line))
            timestamp.extend(re.findall(r"<TimeStamp>(.*?)</TimeStamp>", line))

        postNatIp = ip[0]
        postNatPort = port[0]
        destinationIp = ''
        destinationPort = ''

        if(dest_ip):
            destinationIp = dest_ip[0]
        if(dest_port):
            destinationPort = dest_port[0]

        timestamp = moment.date(timestamp[0]).timezone("US/Eastern").format("YYYY-M-DTHH:mm:ssZ")

    # Timestamp in SQL format
    timestampSQL = moment.date(timestamp).format('YYYY-MM-DD HH:mm:ss')
    timestampSQL1 = moment.date(timestamp).add(minutes=10).format('YYYY-MM-DD HH:mm:ss')
    timestampSQL2 = moment.date(timestamp).add(minutes=-10).format('YYYY-MM-DD HH:mm:ss')

    timesToTest = []

    for i in range(0, 20):
        timesToTest.append(moment.date(timestamp).add(minutes=-10).add(minutes=i))

    # PreNat Candidates
    preNat_candidates = []

    for i in timesToTest:
        hourToFind = moment.date(i).hour+1
        if(hourToFind<10):
            hourToFind =  str('0' + str(hourToFind))

        hourToFind =  str(hourToFind)
        tempCommand = "zgrep \"" + str(i)[:16] + "\" nat_logs/nat.csv.20160321" + str(hourToFind) +".csv.gz | grep \"" + str(postNatIp) + "," + str(postNatPort) + "\""

        commandOutput = os.popen(tempCommand).read()

        preNatFound = re.findall( r'[0-9]+(?:\.[0-9]+){3}', commandOutput )

        for j in preNatFound:
            preNat_candidates.append(j)

    if(preNat_candidates):
        preNat = preNat_candidates[0]
    else:
        print("No Suspects Found in NAT Logs.")
        sys.exit()

    print("Local time (EDT) of infringement: " + timestampSQL)

    preNatIp = str(ipConvert(preNat))
    print("Pre-NAT IP address: " + preNat)

    # MAC Candidate
    cur.execute("SELECT * FROM dhcp WHERE ip_decimal=(%s) AND timestamp>=(%s) AND timestamp<=(%s)", (preNatIp,timestampSQL2,timestampSQL1,))
    curOutput = cur.fetchall()

    if(curOutput[0][1]):
        macCandidate = curOutput[0][1]
        print("MAC address: " + macCandidate)
    else:
        print("No MAC was found.")
        sys.exit()

    # User identify

    if(preNat[4] == '1'):
        cur.execute("SELECT username FROM radacct WHERE FramedIPAddress=(%s) AND timestamp>=(%s) AND timestamp<=(%s)", (preNat,timestampSQL2,timestampSQL1,))
        if(not cur.fetchone()):
            cur.execute("SELECT username FROM radacct WHERE CallingStationId=(%s)", (macCandidate,))
    else:
        cur.execute("SELECT contact FROM contactinfo WHERE mac_string=(%s)", (macCandidate,))

    curOutput = cur.fetchone()

    if(curOutput):
        userCandidate = curOutput[0]
        print("Username: " + userCandidate)
    else:
        print("No user was found.")
        sys.exit()

def ipConvert(ip):

    # Convert ip
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

parse(sys.argv[1])
