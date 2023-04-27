from pyaccesspoint.PyAccessPoint import pyaccesspoint
import socket
import time
import threading
import subprocess
import os
import json
import ctypes
import sys
import logging
import pika


class Connection:
    def __init__(self, user_id, sock, mac, ip):
        self.user_id = user_id
        self.sock = sock
        self.mac = mac
        self.ip = ip

    def __str__(self):
        return f"User ID: {self.user_id} | Socket ID: {self.sock} | MAC: {self.mac} | IP: {self.ip}"


class FEC:
    def __init__(self, gpu, ram, bw, rtt):
        self.gpu = gpu
        self.ram = ram
        self.bw = bw
        self.rtt = rtt
        self.connected_users = []

    def __str__(self):
        return f"GPU: {self.gpu} cores | RAM: {self.ram} GB | BW: {self.bw} kbps | " \
               f"RTT: {self.rtt} ms | Connected users: {self.connected_users}"


class VNF:
    # def __init__(self, source, target, ram, gpu, rtt, bw, previous_node, current_node, fec_linked, user_id):
    #     self.source = source
    #     self.target = target
    #     self.gpu = gpu
    #     self.ram = ram
    #     self.bw = bw
    #     self.rtt = rtt
    #     self.previous_node = previous_node
    #     self.current_node = current_node
    #     self.fec_linked = fec_linked
    #     self.user_id = user_id

    def __init__(self, json_data):
        self.source = json_data['source']
        self.target = json_data['target']
        self.gpu = json_data['gpu']
        self.ram = json_data['ram']
        self.bw = json_data['bw']
        self.rtt = json_data['rtt']
        self.previous_node = json_data['previous_node']
        self.current_node = json_data['current_node']
        self.fec_linked = json_data['fec_linked']
        self.user_id = json_data['user_id']

    def __str__(self):
        return f"Source/Target: {self.source}/{self.target} | GPU: {self.gpu} cores | RAM: {self.ram} GB | " \
               f"BW: {self.bw} kbps | RTT: {self.rtt} ms | " \
               f"Nodes (previous/current): {self.previous_node}/{self.current_node} | Linked to FEC: {self.fec_linked}"


access_point = pyaccesspoint.AccessPoint(wlan='wlan0', ssid='Test301', password='1234567890',
                                         ip='10.0.0.1', netmask='255.255.255.0', inet='eth0')
connections = []

fec_list = []
current_fec_state = FEC(2048, 30, 1000, 1)
my_fec_id = -1
fec_state_changed = True

vnf_list = []

stop = False

control_socket = socket.socket()
rabbit_conn = pika.BlockingConnection(
    pika.ConnectionParameters('147.83.118.153', credentials=pika.PlainCredentials('sergi', 'EETAC2023')))

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.FileHandler('logs/fec.log', mode='w', encoding='utf-8'))
logger.addHandler(logging.StreamHandler(sys.stdout))
logging.getLogger('pika').setLevel(logging.WARNING)


def stop_program(wireshark_if, tshark_if):
    if wireshark_if == "y" or wireshark_if == "":
        os.system("sudo screen -S ap-wireshark -X stuff '^C\n'")
    if tshark_if == "y" or tshark_if == "":
        os.system("sudo screen -S ap-tshark -X stuff '^C\n'")


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
            logger.debug('[D] No users connected')
            time.sleep(12)
        except Exception as e:
            logger.exception(e)


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
    logger.info('[I] MAC ' + mac + ' just connected. Waiting for auth...')
    time.sleep(10)
    if not check_conn(mac):
        logger.info('[I] MAC ' + mac + ' not found. Disconnecting user...')
        os.system('sudo hostapd_cli -i wlan0 -p /tmp/hostapd disassociate ' + mac)  # Disconnect in case of not auth
    else:
        logger.info('[I] MAC ' + mac + ' authenticated. Access granted.')


def serve_client(sock, ip):
    global current_fec_state
    global fec_state_changed
    global vnf_list
    while True:
        if stop:
            break
        data = sock.recv(1024).decode()  # Receive data stream. it won't accept data packet greater than 1024 bytes
        if not data:
            break  # If data is not received break

        logger.info("[I] From UE " + str(ip) + ": " + str(data))
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
                    current_fec_state.connected_users.append(json_data['user_id'])
                    k = 0
                    while k < len(connections):
                        if connections[k].sock == sock:
                            break
                        else:
                            k += 1
                    if k != len(connections):
                        m = 0
                        while m < len(vnf_list):
                            if vnf_list[m]['user_id'] == connections[k].user_id:
                                break
                            else:
                                m += 1
                        if m != len(vnf_list):
                            logger.info('[I] Assigning resources for ' + ip + '...')
                            current_fec_state.ram -= vnf_list[m]['ram']
                            current_fec_state.gpu -= vnf_list[m]['gpu']
                            current_fec_state.bw -= vnf_list[m]['bw']
                            fec_state_changed = True
                    fec_state_changed = True
                    if my_fec_id == -1:
                        sock.send(json.dumps(dict(res=500)).encode())  # FEC not connected to Control
                    else:
                        sock.send(json.dumps(dict(res=200, id=my_fec_id)).encode())  # Access granted
                else:
                    sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error reported by Control
            except ValueError:
                sock.send(json.dumps(dict(res=404)).encode())  # Wrong query format
        elif json_data['type'] == 'vnf':
            try:
                if json_data['data']['target'] != json_data['data']['current_node']:
                    state_vector = dict(source=json_data['data']['source'], target=json_data['data']['target'],
                                        gpu=json_data['data']['gpu'], ram=json_data['data']['ram'],
                                        bw=json_data['data']['bw'], rtt=json_data['data']['rtt'],
                                        previous_node=json_data['data']['previous_node'],
                                        current_node=json_data['data']['current_node'],
                                        fec_linked=json_data['data']['fec_linked'], fec_a_res=fec_list[0],
                                        fec_b_res=fec_list[1])
                    logger.debug('[D] State vector to send to Model plane: ' + str(state_vector))
                    # MODEL PLANE: GET ACTION
                    action = 'r'
                else:
                    # REACHED DESTINATION. NO NEED TO USE MODEL PLANE
                    action = 'e'

                control_socket.send(json.dumps(dict(type="vnf", data=json_data['data'])).encode())
                control_response = json.loads(control_socket.recv(1024).decode())
                if control_response['res'] == 200:
                    i = 0
                    while i < len(connections):
                        if connections[i].sock == sock:
                            break
                        else:
                            i += 1
                    if i == len(connections):
                        logger.error('[!] Trying to assign resources to unknown user!')
                    else:
                        j = 0
                        while j < len(vnf_list):
                            if vnf_list[j]['user_id'] == connections[i].user_id:
                                break
                            else:
                                j += 1
                        if j == len(vnf_list):
                            logger.info('[I] Assigning resources for ' + ip + '...')
                            current_fec_state.ram -= json_data['data']['ram']
                            current_fec_state.gpu -= json_data['data']['gpu']
                            current_fec_state.bw -= json_data['data']['bw']
                            fec_state_changed = True
                        if action == 'e':
                            logger.info('[I] Releasing resources from ' + ip + '...')
                            current_fec_state.ram += vnf_list[j]['ram']
                            current_fec_state.gpu += vnf_list[j]['gpu']
                            current_fec_state.bw += vnf_list[j]['bw']
                            fec_state_changed = True
                    sock.send(json.dumps(dict(res=200, action=action)).encode())  # Access granted
                else:
                    sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error reported by Control
            except ValueError:
                sock.send(json.dumps(dict(res=404)).encode())  # Wrong query format
        elif json_data['type'] == 'bye':  # Disconnect. Format: {"type": "bye"}
            break
        else:
            sock.send(json.dumps(dict(res=400)).encode())  # Bad request

    found = False
    i = 0
    while not found and i < len(connections):
        if connections[i].sock == sock:
            found = True
        else:
            i += 1
    if found:
        j = 0
        while j < len(vnf_list):
            if vnf_list[j]['user_id'] == connections[i].user_id:
                break
            else:
                j += 1
        if j < len(vnf_list):
            current_fec_state.ram += vnf_list[j]['ram']
            current_fec_state.gpu += vnf_list[j]['gpu']
            current_fec_state.bw += vnf_list[j]['bw']
            logger.info('[I] Releasing resources from ' + ip + '...')
        logger.info('[I] User ' + ip + ' disconnected.')
        current_fec_state.connected_users.remove(connections[i].user_id)
        fec_state_changed = True
        connections.pop(i)
    else:
        logger.error('[!] Disconnected unknown valid user!')
    sock.close()  # Close the connection


def subscribe(conn, key_string):
    channel = conn.channel()

    channel.exchange_declare(exchange='test', exchange_type='direct')

    queue = channel.queue_declare(queue='', exclusive=True).method.queue

    keys = key_string.split(' ')
    for key in keys:
        channel.queue_bind(
            exchange='test', queue=queue, routing_key=key)

    logger.info('[I] Waiting for published data...')

    def callback(ch, method, properties, body):
        global fec_list
        global vnf_list
        logger.debug("[D] Received message. Key: " + str(method.routing_key) + ". Message: " + body.decode("utf-8"))
        if str(method.routing_key) == 'fec':
            fec_list = json.loads(body.decode('utf-8'))
        elif str(method.routing_key) == 'vnf':
            vnf_list = json.loads(body.decode('utf-8'))

    channel.basic_consume(
        queue=queue, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()


def kill_thread(thread_id):
    killed_threads = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), ctypes.py_object(SystemExit))
    if killed_threads == 0:
        raise ValueError("Thread ID " + str(thread_id) + " does not exist!")
    elif killed_threads > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
    logger.debug('[D] Successfully killed thread ' + str(thread_id))


subscribe_thread = threading.Thread(target=subscribe, args=(rabbit_conn, 'fec vnf'))


def control_conn():
    try:
        global current_fec_state
        global fec_state_changed
        global my_fec_id

        subscribe_thread.daemon = True
        subscribe_thread.start()

        host = '147.83.118.153'
        port = 5000

        control_socket.connect((host, port))

        control_socket.send(json.dumps(dict(type="id")).encode())
        response = json.loads(control_socket.recv(1024).decode())
        if response['res'] == 200:
            logger.info('[I] My ID is: ' + str(response['id']))
            my_fec_id = response['id']
        else:
            logger.error('[!] Error from Control' + response['res'])

        while True:
            if fec_state_changed:
                logger.info('[I] New current FEC state! Sending to control...')
                control_socket.send(json.dumps(dict(type="fec", data=current_fec_state.__dict__)).encode())
                response = json.loads(control_socket.recv(1024).decode())
                if response['res'] != 200:
                    logger.error('[!] Error from Control:' + response['res'])
                fec_state_changed = False
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
    except Exception as e:
        logger.exception(e)


control_conn_thread = threading.Thread(target=control_conn)


def main():
    tshark_if = 'n'
    wireshark_if = 'n'
    try:
        script_path = os.path.dirname(os.path.realpath(__file__))
        script_path = script_path + "/"
        os.system("sudo mkdir " + script_path + "logs > /dev/null 2>&1")
        os.system("sudo chmod 777 " + script_path + "logs")
        # UPDATE QUESTION
        update = input("[?] Install/Update dependencies? Y/n: (n)")
        update = update.lower()
        if update == "y":
            logger.info("[I] Checking/Installing dependencies, please wait...")
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
        wireshark_if = input("[?] Start WIRESHARK on wlan0? Y/n: (Y)")
        wireshark_if = wireshark_if.lower()
        if wireshark_if != "y" and wireshark_if != "":
            tshark_if = input("[?] Capture packets to .pcap with TSHARK? (no gui needed) Y/n: (Y)")
            tshark_if = tshark_if.lower()
        # /WIRESHARK & TSHARK QUESTION

        # START AP
        logger.info("[I] Starting AP on wlan0...")
        access_point.start()
        if wireshark_if == "y" or wireshark_if == "":
            logger.info("[I] Starting Wireshark...")
            os.system("sudo screen -S ap-wireshark -m -d wireshark -i wlan0 -k -w " + script_path +
                      "logs/ap-wireshark.pcap")
        if tshark_if == "y" or tshark_if == "":
            logger.info("[I] Starting Tshark...")
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
            logger.info("[I] New connection from: " + str(address))
            socket_thread = threading.Thread(target=serve_client, args=(conn, address[0]))
            socket_thread.daemon = True
            socket_thread.start()
    except KeyboardInterrupt:
        logger.info("\n\n[!] Stopping... (Dont worry if you get errors)")
        stop = True
        kill_thread(control_conn_thread.ident)
        for connection in connections:
            connection.sock.close()
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        logger.info("[I] AP stopped.")
    except OSError:
        logger.critical("\n\n[!] Error when binding address and port for server! Stopping...")
        stop = True
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        logger.info("[I] AP stopped.")
    except Exception as e:
        logger.exception(e)


if __name__ == '__main__':
    main()
