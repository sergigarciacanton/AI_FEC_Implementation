from pyaccesspoint.PyAccessPoint import pyaccesspoint
import socket
import time
import threading
import subprocess
import os
import json
import pika
import ctypes


access_point = pyaccesspoint.AccessPoint(wlan='wlan0', ssid='Test301', password='1234567890',
                                         ip='10.0.0.1', netmask='255.255.255.0', inet='eth0')
connections = []
valid_ids = [1, 2, 3]
stop = False


class Connection:
    def __init__(self, user_id, sock, mac, ip):
        self.user_id = user_id
        self.sock = sock
        self.mac = mac
        self.ip = ip

    def __str__(self):
        return f"User ID: {self.user_id} | Socket ID: {self.sock} | MAC: {self.mac} | IP: {self.ip}"


class Fec:
    def __init__(self, gpu, ram, bw, rtt):
        self.gpu = gpu
        self.ram = ram
        self.bw = bw
        self.rtt = rtt
        self.connected_users = []

    def __str__(self):
        return f"GPU: {self.gpu} cores | RAM: {self.ram} GB | BW: {self.bw} kbps | " \
               f"RTT: {self.rtt} ms | Connected users: {self.connected_users}"


def stop_program(wireshark_if, tshark_if):
    try:
        if wireshark_if == "y" or wireshark_if == "":
            os.system("sudo screen -S ap-wireshark -X stuff '^C\n'")
    except:
        pass
    try:
        if tshark_if == "y" or tshark_if == "":
            os.system("sudo screen -S ap-tshark -X stuff '^C\n'")
    except:
        pass


def listen_new_conn():
    while not stop:
        try:
            output = subprocess.check_output("iw dev wlan0 station dump | grep Station", shell=True).decode()
            macs = []
            for line in output.split('\n'):
                if line != '':
                    macs.append(line.split()[1])
            for mac in macs:
                if not check_conn(mac):
                    disconnect_thread = threading.Thread(target=manage_new_conn, args=(mac,))
                    disconnect_thread.daemon = True
                    disconnect_thread.start()
            time.sleep(12)
        except KeyboardInterrupt:
            pass
        except subprocess.CalledProcessError:
            print('[I] No users connected')
            time.sleep(12)


def check_conn(mac):
    i = 0
    found = False
    while not found and i < len(connections):
        if connections[i].mac == str(mac):
            found = True
        else:
            i += 1
    return found


def manage_new_conn(mac):
    print('[!] MAC ' + mac + ' just connected. Waiting for auth...')
    time.sleep(10)
    if not check_conn(mac):
        print('[!] MAC ' + mac + ' not found. Disconnecting user...')
        os.system('sudo hostapd_cli -i wlan0 -p /tmp/hostapd disassociate ' + mac)  # Disconnect in case of not auth
    else:
        print('[I] MAC ' + mac + ' authenticated. Access granted.')


def serve_client(sock, ip):
    global current_state
    global state_changed
    while True:
        if stop:
            break
        data = sock.recv(1024).decode()  # Receive data stream. it won't accept data packet greater than 1024 bytes
        if not data:
            break  # If data is not received break

        print("[I] From UE " + str(ip) + ": " + str(data))
        json_data = json.loads(data)

        if json_data['type'] == 'auth':  # Finish setting up connection. Format: {"type": "auth", "user_id": 1}
            try:
                control_socket.send(json.dumps(dict(type="auth", user_id=json_data['user_id'])).encode())
                control_response = json.loads(control_socket.recv(1024).decode())
                if control_response['res'] == 200:
                    connections.append(Connection(int(json_data['user_id']),
                                                  sock,
                                                  subprocess.check_output(['arp', '-n', ip]).decode().split('\n')[
                                                      1].split()[2],
                                                  ip))
                    current_state.connected_users.append(json_data['user_id'])
                    state_changed = True
                    sock.send(json.dumps(dict(res=200)).encode())  # Access granted
                else:
                    sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error reported by Control
            except ValueError:
                sock.send(json.dumps(dict(res=404)).encode())  # Wrong query

        else:
            sock.send(json.dumps(dict(res=400)).encode())

    found = False
    i = 0
    while not found and i < len(connections):
        if connections[i].sock == sock:
            found = True
        else:
            i += 1
    if found:
        print('[I] User ' + ip + ' disconnected.')
        current_state.connected_users.remove(connections[i].user_id)
        state_changed = True
        connections.pop(i)
    else:
        print('[!] User not found when disconnecting!')
    sock.close()  # Close the connection


def subscribe(conn, key):
    channel = conn.channel()

    channel.exchange_declare(exchange='test', exchange_type='direct')

    queue = channel.queue_declare(queue='', exclusive=True).method.queue

    channel.queue_bind(
        exchange='test', queue=queue, routing_key=key)

    print('[I] Waiting for published data...')

    def callback(ch, method, properties, body):
        print("[I] Received message. Key: " + str(method.routing_key) + ". Message: " + body.decode("utf-8"))

    channel.basic_consume(
        queue=queue, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()


def kill_thread(thread_id):
    killed_threads = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), ctypes.py_object(SystemExit))
    if killed_threads == 0:
        raise ValueError("Thread ID " + str(thread_id) + " does not exist!")
    elif killed_threads > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
    print('[I] Successfully killed thread ' + str(thread_id))


def control_conn():
    try:
        global current_state
        global state_changed
        subscribe_thread.daemon = True
        subscribe_thread.start()

        host = '147.83.118.153'
        port = 5000

        control_socket.connect((host, port))

        control_socket.send(json.dumps(dict(type="id")).encode())
        response = json.loads(control_socket.recv(1024).decode())
        if response['res'] == 200:
            print('[I] My ID is: ' + str(response['id']))
        else:
            print('[!] Error ' + response['res'])

        while True:
            if state_changed:
                print('[I] New current state! Sending to control...')
                control_socket.send(json.dumps(dict(type="fec", data=current_state.__dict__)).encode())
                response = json.loads(control_socket.recv(1024).decode())
                if response['res'] != 200:
                    print('[!] Error ' + response['res'])
                state_changed = False
    except KeyboardInterrupt:
        kill_thread(subscribe_thread.ident)
        subscribe_thread.join()
        rabbit_conn.close()
        control_socket.close()
    except SystemExit:
        kill_thread(subscribe_thread.ident)
        subscribe_thread.join()
        rabbit_conn.close()
        control_socket.close()


fec_list = []
control_socket = socket.socket()
rabbit_conn = pika.BlockingConnection(
    pika.ConnectionParameters('147.83.118.153', credentials=pika.PlainCredentials('sergi', 'EETAC2023')))
subscribe_thread = threading.Thread(target=subscribe, args=(rabbit_conn, 'fec'))
current_state = Fec(2048, 30, 1000, 1)
control_conn_thread = threading.Thread(target=control_conn)
state_changed = False


def main():
    tshark_if = 'n'
    wireshark_if = 'n'
    try:
        script_path = os.path.dirname(os.path.realpath(__file__))
        script_path = script_path + "/"
        os.system("sudo mkdir " + script_path + "logs > /dev/null 2>&1")
        os.system("sudo chmod 777 " + script_path + "logs")
        # UPDATE QUESTION
        update = input("[?] Install/Update dependencies? Y/n: ")
        update = update.lower()
        if update == "y":
            print("[I] Checking/Installing dependencies, please wait...")
            os.system("sudo apt-get update")
            os.system("sudo apt-get install dnsmasq -y")
            os.system("sudo apt-get install wireshark -y")
            os.system("sudo apt-get install hostapd -y")
            os.system("sudo apt-get install screen -y")
            os.system("sudo apt-get install python-pip -y")
            os.system("sudo apt-get install python3-pip -y")
            os.system("sudo apt-get install python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev "
                      "libjpeg62-turbo-dev zlib1g-dev -y")
            os.system("sudo apt-get install libpcap-dev -y")
            os.system("sudo python -m pip install pcapy")
        # /UPDATE QUESTION

        # WIRESHARK & TSHARK QUESTION
        wireshark_if = input("[?] Start WIRESHARK on wlan0? Y/n: ")
        wireshark_if = wireshark_if.lower()
        if wireshark_if != "y" and wireshark_if != "":
            tshark_if = input("[?] Capture packets to .pcap with TSHARK? (no gui needed) Y/n: ")
            tshark_if = tshark_if.lower()
        # /WIRESHARK & TSHARK QUESTION

        # START AP
        print("[I] Starting AP on wlan0...")
        access_point.start()
        if wireshark_if == "y" or wireshark_if == "":
            print("[I] Starting WIRESHARK...")
            os.system("sudo screen -S ap-wireshark -m -d wireshark -i wlan0 -k -w " + script_path +
                      "logs/ap-wireshark.pcap")
        if tshark_if == "y" or tshark_if == "":
            print("[I] Starting TSHARK...")
            os.system("sudo screen -S ap-tshark -m -d tshark -i wlan0 -w " + script_path +
                      "logs/ap-tshark.pcap")
        # /START AP

        time.sleep(5)

        global stop
        stop = False
        new_conn_thread = threading.Thread(target=listen_new_conn)
        new_conn_thread.daemon = True
        new_conn_thread.start()

        # Server's IP and port
        # host = '147.83.118.154'
        host = '10.0.0.1'
        port = 5010

        server_socket = socket.socket()  # Create socket
        server_socket.bind((host, port))  # Bind IP address and port together

        # Configure how many client the server can listen simultaneously
        server_socket.listen(1)

        control_conn_thread.daemon = True
        control_conn_thread.start()

        # Infinite loop listening for new connections
        while True:
            conn, address = server_socket.accept()  # Accept new connection
            print("Connection from: " + str(address))
            socket_thread = threading.Thread(target=serve_client, args=(conn, address[0]))
            socket_thread.daemon = True
            socket_thread.start()
    except KeyboardInterrupt:
        print("\n\n[!] Stopping... (Dont worry if you get errors)")
        stop = True
        kill_thread(control_conn_thread.ident)
        for connection in connections:
            connection.sock.close()
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        print("[I] AP stopped.")
    except OSError:
        print("\n\n[!] Error when binding address and port for server! Stopping...")
        stop = True
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        print("[I] AP stopped.")


if __name__ == '__main__':
    main()
