import socket
import threading
import select
import os
import re
import uuid
import calendar
import datetime
import hashlib
from cmd import Cmd
from time import sleep
from random import randint
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from ftplib import FTP
from tabulate import tabulate



#GLOBAL
MAXIMUM_SEARCH_TIME=10
SEGMENT_HEADER_SIZE=10
IP_ADDDRESS="0.0.0.0"
PORT=6880
NODE_MAC_ADDRESS=hex(uuid.getnode())
NODE_UNIQUE_ADDRESS=NODE_MAC_ADDRESS+":"+str(PORT)
NODE_ID=hashlib.md5(NODE_UNIQUE_ADDRESS.encode()).hexdigest()
FTP_IP="0.0.0.0"
FTP_PORT=1026
SEARCH_RESULTS={}
PUBLIC_FOLDER="public"
DOWNLOADS_FOLDER="downloads"
node_id_to_socket_conn= {}
lock=threading.RLock()
message_history={}




def exposeGnutellaPort():
    sock=socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((IP_ADDDRESS,PORT))
    sock.listen(50)
    (ip,port)=sock.getsockname()

    print("gnutella started ID "+NODE_ID+", running at port 6880")
    while True:
        clientsock, clientAddress = sock.accept()
        newthread = ConnectionThread(clientAddress, clientsock)
        newthread.daemon = True
        error=newthread.start()
        if error:
            raise SystemExit
        greeting_payload=newthread.prepare_greeting_payload()
        newthread.send(greeting_payload)


def open_ftp():
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(PUBLIC_FOLDER)
    handler = FTPHandler
    handler.authorizer = authorizer
    server = FTPServer((FTP_IP, FTP_PORT), handler)
    server.serve_forever()


def check_file(filename):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    public_folder=os.path.join(dir_path,PUBLIC_FOLDER)

    for f in os.listdir(public_folder):
        if os.path.isfile(os.path.join(public_folder, f)) and f==filename:
            unique_filename=NODE_UNIQUE_ADDRESS+f
            return True,hashlib.md5(unique_filename.encode()).hexdigest() 
    return False,None

def get_all_connections():
    all_threads=threading.enumerate()
    connections=[]
    for i in range(3,len(all_threads)):
        connections.append(all_threads[i])
    return connections

def generate_msgid(n=10):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return str(randint(range_start, range_end))

def download_file(ip,port,filename):
    ftpClient = FTP('')
    ftpClient.connect(ip,port)
    ftpClient.login()
    ftpClient.cwd('./')

    #checking if file name already present in local and save in new file name
    # but before that split extension,from file name
    filename_array=filename.split('.')
    filename_extension=filename_array[-1]
    del filename_array[-1]
    filename_without_extension='.'.join(filename_array)
    localfile=filename
    i = 0
    while os.path.exists("./"+DOWNLOADS_FOLDER+"/"+localfile):
        i += 1
        localfile=filename_without_extension+" ("+str(i)+")."+filename_extension    
    localfile = open(DOWNLOADS_FOLDER+"/"+localfile,'wb')
    
    try:
        ftpClient.retrbinary('RETR ' + filename, localfile.write, 1024)
    except:
        print('requested file not found')
        
    ftpClient.quit()
    localfile.close()

def clean_string(input):
    a=input.translate(''.join([',',':'])) 
    return a

class ConnectionError(Exception):
    pass


class ConnectionThread(threading.Thread):
    
    def __init__(self,clientAddress,clientsocket):
        threading.Thread.__init__(self)
        self.client_ip=clientAddress
        self.socket = clientsocket
        self.killed_cmd_initiated=False
        self.buffered_data =""


    def run(self):
        """runs at the start of the thread"""
        while True:
            self.buffered_data += self.recv(1000)
            self.process_new_data()
          
            if self.killed_cmd_initiated:
                return

                
    def process_new_data(self):
        """Process data to split it into messages"""

        #if atleast header came
        while self.buffered_data[SEGMENT_HEADER_SIZE-1:]:
            payload_length_string= self.buffered_data[:SEGMENT_HEADER_SIZE]
            payload_length = int(payload_length_string)

            #throw error if packet size is large
            if payload_length+SEGMENT_HEADER_SIZE > 1000 :
                raise ConnectionError("Packet over 1kb, should be packet size should be under 1kb")

            #process payload
            payload = self.buffered_data[SEGMENT_HEADER_SIZE:SEGMENT_HEADER_SIZE+payload_length]
            self.process_new_packet(payload)
            
            # remove the packet from the buffered_data. 
            self.buffered_data = self.buffered_data[SEGMENT_HEADER_SIZE+payload_length:]
            break


    def process_new_packet(self,payload):
        """extract and process data from packets"""

        hash_value=payload[-32:]
        payload = payload[:-32]

        #ignore the packet if it is broken or modified
        if hash_value != hashlib.md5(payload.encode()).hexdigest():
            return
            
            
        payload_array=payload.split(',')
        data={}
        for p_array in payload_array:
            key_value=p_array.split(':')
            data[key_value[0]]=key_value[1]

        #if message is already seen ignore:
        if data['msg_id'] in message_history:
            return
        else:
            message_history[data['msg_id']]=1
 

        if data['payload_type'] == 'greeting':
            self.process_greeting_payload(data)
        elif data['payload_type'] == 'query':
            self.process_query_payload(data)
        elif data['payload_type'] == 'query_hit':
            self.process_query_hit_payload(data)
        elif data['payload_type']=='download':
            send_file(data)
        elif data['payload_type']=='bye':
            with lock:
                del node_id_to_socket_conn[data['node_id']]
                self.socket.close()
                self.killed_cmd_initiated=True


    def send(self, data, flush = True):
        """Send packets to connection"""
        try:
            self.socket.send(data.encode())
        except:
            print('client disconnected')
            self.socket.close()
            self.killed_cmd_initiated=True


    def recv(self, max_len=1000):
        """Receive packets from connection"""

        data = self.socket.recv(max_len)
        return data.decode()


    def process_greeting_payload(self,data):
        """ get the connecting node details """

        #checking if connection made from same node
        if data['mac'] == NODE_MAC_ADDRESS and data['port'] == str(PORT):
            print("killing process. cannot connect to itself")
            self.killed_cmd_initiated=True
            return

        with lock:        
            node_id_to_socket_conn[data['node_id']]=threading.current_thread()


    def process_query_payload(self,data):
        """ process query"""
        
        #ignore the packet if it is expired
        current_datetime = datetime.datetime.now()
        expiry_datetime = datetime.datetime.fromtimestamp(int(data['expiry']))

        if expiry_datetime < current_datetime:
            return

        #check if search text is present and send query_hit to query initiator
        file_found,file_id,=check_file(data['filename'])
        if file_found:
            #check for connection
            client_address=data['node_id']
            if client_address in node_id_to_socket_conn:
                conn=node_id_to_socket_conn[client_address]
                query_hit_payload=conn.prepare_query_hit_payload(data,file_id)  
                conn.send(query_hit_payload)   
            
            else:
                #if not found create a temp connection to the initiator node
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                try:
                    sock.connect((data['ip'],int(data['port'])))
                except socket.error:
                    print('cannot connect to specified socket.')
                    return 
                query_hit_payload=self.prepare_query_hit_payload(data,file_id)
                sock.send(query_hit_payload.encode())
                sock.close()

        #forward query request to all other conn
        all_connections=get_all_connections()
        for conn in all_connections:
            if conn.client_ip == self.client_ip:
                continue
            query_payload=conn.prepare_query_payload(data)
            conn.send(query_payload)


    def process_query_hit_payload(self,data):
        """process query hit"""
    
        result = [data['filename'], data['file_id'],data['node_id']]
        print(tabulate([result],[], tablefmt="plain"))
        with lock:
            SEARCH_RESULTS[data['file_id']]=(data['ftp_ip'],int(data['ftp_port']),data['filename'])
        print("\n")


    def prepare_greeting_payload(self):
        """greeting payload construction"""

        payload="node_id:"+NODE_ID+","
        payload+="msg_id:"+generate_msgid()+","
        payload+="payload_type:greeting,"
        payload+="mac:"+NODE_MAC_ADDRESS+","
        payload+="port:"+str(PORT)
        payload+=hashlib.md5(payload.encode()).hexdigest()
        payload_length=len(payload)
        payload=f'{payload_length:<{SEGMENT_HEADER_SIZE}}'+payload
        return payload


    def prepare_query_payload(self,data):
        """query payload construction """

        payload="node_id:"+data['node_id']+","
        payload+="msg_id:"+data['msg_id']+","
        payload+="expiry:"+data['expiry']+","
        payload+="ip:"+data['ip']+","
        payload+="port:"+data['port']+","
        payload+="payload_type:query,"
        payload+="filename:"+data['filename']
        payload+=hashlib.md5(payload.encode()).hexdigest()
        payload_length=len(payload)
        payload=f'{payload_length:<{SEGMENT_HEADER_SIZE}}'+payload
        return payload

    def prepare_query_hit_payload(self,data,file_id):
        """query_hit payload construction """

        payload="node_id:"+NODE_ID+","
        payload+="msg_id:"+generate_msgid()+","
        payload+="ip:"+data['ip']+","
        payload+="port:"+data['port']+","
        payload+="payload_type:query_hit,"
        payload+="filename:"+data['filename']+","
        payload+="file_id:"+file_id+","
        payload+="ftp_ip:"+FTP_IP+","
        payload+="ftp_port:"+str(FTP_PORT)
        payload+=hashlib.md5(payload.encode()).hexdigest()
        payload_length=len(payload)
        payload=f'{payload_length:<{SEGMENT_HEADER_SIZE}}'+payload
        return payload

    def prepare_bye_payload(self,data):
        """bye payload construction """

        payload="node_id:"+NODE_ID+","
        payload+="msg_id:"+generate_msgid()+","
        payload+="ip:"+data['ip']+","
        payload+="port:"+data['port']+","
        payload+="payload_type:bye"
        payload+=hashlib.md5(payload.encode()).hexdigest()
        payload_length=len(payload)
        payload=f'{payload_length:<{SEGMENT_HEADER_SIZE}}'+payload
        return payload

        

class GnutellaNetwork(Cmd):

    def __int__(self):
        super().__init__()


    def launch(self):
        #gnutella expose thread
        thread = threading.Thread(target=exposeGnutellaPort)
        thread.daemon = True
        thread.start()
        
        #ftp server thread
        thread2 = threading.Thread(target=open_ftp)
        thread2.daemon= True
        thread2.start()
        

    def open(self,client_ip,client_port):
        """connects to a node on the network. usage: open <host:port>"""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((client_ip,client_port))
        except socket.error:
            print('cannot connect to specified socket.')
            return 

        newthread = ConnectionThread((client_ip,client_port), sock)
        newthread.daemon = True
        newthread.start()
        print ("New connection added: ",(client_ip,client_port))
        greeting_payload=newthread.prepare_greeting_payload()
        newthread.send(greeting_payload)


    def close(self,node_id):
        """closes connection by connection id. usage: close <id>"""

        global node_id_to_socket_conn

        if node_id in node_id_to_socket_conn:
            conn=node_id_to_socket_conn[node_id]
            data={
                "ip":IP_ADDDRESS,
                "port":str(PORT),
            }
            bye_payload=conn.prepare_bye_payload(data)
            conn.send(bye_payload)
            conn.socket.close()
            conn.killed_cmd_initiated=True
            del node_id_to_socket_conn[node_id]
            print("connection closed")
        else:
            print("no connection found with specified ID")


    def info_connections(self):
        """shows list of connected hosts with an id for each"""

        headers = ["node_id", "client address"]
        rows=[]
        for node_id, conn in node_id_to_socket_conn.items():
            rows.append([node_id,conn.client_ip[0]+":"+str(conn.client_ip[1])])
        print(tabulate(rows,headers, tablefmt="plain"))


    def find(self,file_name):
        """search files on the network and lists results. usage: find <file name>"""

        expiry_datetime=datetime.datetime.now()+datetime.timedelta(seconds=MAXIMUM_SEARCH_TIME)
        data={
            "node_id":NODE_ID,
            "msg_id":generate_msgid(),
            "expiry":str(int(expiry_datetime.timestamp())),
            "ip":IP_ADDDRESS,
            "port":str(PORT),
            "filename":file_name
        }

        print("searching......")
        print("press ctrl+c to stop")
        headers = ["file_name", "file_id","node_id"]
        print(tabulate([], headers, tablefmt="plain"))
        
        connections=get_all_connections()
        for conn in connections:
            query_payload=conn.prepare_query_payload(data)
            conn.send(query_payload)

        if len(connections)==0:
            print('not connected to any node')
            return 
        try:
            while True:
                sleep(5)
        except KeyboardInterrupt:
            pass


    def get(self,file_id):
        """Download a file by id. usage: get <file id>"""

        if file_id in SEARCH_RESULTS:
            download_file(SEARCH_RESULTS[file_id][0],SEARCH_RESULTS[file_id][1],SEARCH_RESULTS[file_id][2])
            print('file downloaded....')
    

if __name__ == "__main__":

    #create required folders if not exist 
    if not os.path.exists('public'):
        os.makedirs('public')
    if not os.path.exists('downloads'):
        os.makedirs('downloads')
        
    gnutella = GnutellaNetwork()
    gnutella.launch()

    while True:
        user_command = input(">") 
        
        open_conn = re.match("open (.*?):(\d*)", user_command)
        close=re.match("close (.*)", user_command)
        find=re.match("find (.*)", user_command)
        get=re.match("get (.*)", user_command)

        if user_command == '':
            continue

        elif user_command == 'quit':
            print("Quitting.")
            raise SystemExit

        elif open_conn:
            client_ip=clean_string(open_conn.group(1))
            client_port=int(clean_string(open_conn.group(2)))
            gnutella.open(client_ip,client_port)

        elif close:
            gnutella.close(clean_string(close.group(1)))

        elif user_command == 'info connections':
            gnutella.info_connections()
        
        elif find:
            gnutella.find(clean_string(find.group(1))) 
    
        elif get:
            gnutella.get(clean_string(get.group(1))) 
        
        elif user_command == 'help':
            print("open             - connects to a node on the network. usage: open <host:port>")
            print("close            - closes connection by connection id. usage: close <id>")
            print("info connections - shows list of connected hosts with an id for each")
            print("find             - search files on the network and lists results. usage: find <file name>")
            print("get              - download a file by id. usage: get <file id>")
            print("quit             - close the application")
            
        else:
            print('command not found')


    
