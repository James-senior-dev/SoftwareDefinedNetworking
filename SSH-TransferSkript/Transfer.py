import socket
import ipaddress
import http.client
import json
import time
import paramiko
from scp import SCPClient

class StaticEntryPusher(object):

    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticentrypusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
        }
        body = json.dumps(data)
        conn = http.client.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        print(ret)
        conn.close()
        return ret

def check_file(path):
    try:
        f = open(path)
        return True
    except FileNotFoundError:
        print("Solch eine Datei ist nicht vorhanden!")
        return False
    finally:
        try:
            f.close()
        except UnboundLocalError:
            pass

def check_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        print("Die IP-Adresse {} ist gueltig.".format(address))
        return True
    except ValueError:
        print("Die IP-Adresse {} ist nicht gueltig.".format(address))
        return False

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('192.168.2.1', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

source_ip = get_ip()

valid = False
while not valid:
    file_path = str(input(
        "Pfad der Datei zum Transfer eingeben (Beispiel:/home/username/Schreibtisch/file)\n"))
    valid = check_file(file_path)

valid = False
while not valid:
    destination_ip = str(
        input("IPv4-Adresse des Ziels eingeben(Beispiel:192.168.1.1)\n"))
    valid = check_ip(destination_ip)

destination_host_name = str(input('Hostname fuer die IP %s eingeben\n' % destination_ip))

destination_pass = str(input('Passwort fuer Host %s eingeben\n' % destination_host_name))

file_path_remote = str(input(
    "Pfad, wohin Datei bei Remote gespeichert (Beispiel:/home/username/Schreibtisch/file)\n"))

pusher=StaticEntryPusher('192.168.1.20')

prio1_dst={
    'switch': "00:00:00:00:00:00:00:01",
    "name": "prio1_dst",
    "priority": "32768",
	"eth_type": "0x0800",
	"ip_proto": "6",
	"tcp_dst": "22",
	"ipv4_dst": destination_ip,
	"ipv4_src": source_ip,
	"active": "true",
	"actions": "output=normal"
}

prio1_src={
    'switch': "00:00:00:00:00:00:00:01",
    "name": "prio1_src",
    "priority": "32768",
	"eth_type": "0x0800",
	"ip_proto": "6",
	"tcp_src": "22",
	"ipv4_dst": source_ip,
	"ipv4_src": destination_ip,
	"active": "true",
	"actions": "output=normal"
}

dros1={
    'switch': "00:00:00:00:00:00:00:01",
    "name": "dros1",
    "priority": "1050",
	"eth_type": "0x0800",
	"active": "true",
	"actions": "set_queue=2,output=normal"
}

prio2_dst={
    'switch': "00:00:00:00:00:00:00:02",
    "name": "prio2_dst",
    "priority": "32768",
	"eth_type": "0x0800",
	"ip_proto": "6",
	"tcp_dst": "22",
	"ipv4_dst": destination_ip,
	"ipv4_src": source_ip,
	"active": "true",
	"actions": "output=normal"
}

prio2_src={
    'switch': "00:00:00:00:00:00:00:02",
    "name": "prio2_src",
    "priority": "32768",
	"eth_type": "0x0800",
	"ip_proto": "6",
	"tcp_src": "22",
	"ipv4_dst": source_ip,
	"ipv4_src": destination_ip,
	"active": "true",
	"actions": "output=normal"
}

dros2={
    'switch': "00:00:00:00:00:00:00:02",
    "name": "dros2",
    "priority": "1050",
	"eth_type": "0x0800",
	"active": "true",
	"actions": "set_queue=2,output=normal"
}

pusher.set(prio1_dst)
pusher.set(prio1_src)
pusher.set(dros1)
pusher.set(prio2_dst)
pusher.set(prio2_src)
pusher.set(dros2)

def createSSHClient(server, port, user, password):
    client=paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, password)
    return client

ssh=createSSHClient(server=destination_ip, port=22,
                    user=destination_host_name, password=destination_pass)
scp=SCPClient(ssh.get_transport())

scp.put(file_path, remote_path=file_path_remote,
    recursive=False, preserve_times=False)