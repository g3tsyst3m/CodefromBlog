import socket
import subprocess
import sys
import time
import threading
import asyncio
import io
import os
#import readline
import colorama
from colorama import Fore, Back, Style

def shellreceiver(conn):
    while True:
        try:
            data=conn.recv(1)
            print(data.decode(), end="", flush=True)
        except:
            print("server/socket must have died...time to hop off")
            conn.close()
            os._exit(0) 
def shellsender(conn):
    while True:
        mycmd=input("")
        mycmd=mycmd+"\n"
        try:
            conn.send(mycmd.encode())
        except:
            print("server/socket must have died...time to hop off")
            conn.close()
            os._exit(0) 


host = "0.0.0.0"
port = 4546

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

conn, addr = s.accept()
print(Fore.GREEN, f'\n[*] Accepted new connection from: {addr[0]}:{addr[1]}', Fore.WHITE)

s2p_thread = threading.Thread(target=shellreceiver, args=[conn, ])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellsender, args=[conn, ])
s2p_thread.daemon = True
s2p_thread.start()

while True:
    time.sleep(1)
