import configparser
import psutil
import torch
from colorlog import ColoredFormatter
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
    def __init__(self, gpu, ram, bw):
        self.gpu = gpu
        self.ram = ram
        self.bw = bw
        self.connected_users = []

    def __str__(self):
        return f"GPU: {self.gpu} cores | RAM: {self.ram} GB | BW: {self.bw} kbps |" \
               f" Connected users: {self.connected_users}"


config = configparser.ConfigParser()
config.read("fec_outdoor.ini")
general = config['general']
scenario_if = 0
locations = config['general']

logger = logging.getLogger('')
logger.setLevel(int(general['log_level']))
logger.addHandler(logging.FileHandler(general['log_file_name'], mode='w', encoding='utf-8'))
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(ColoredFormatter('%(log_color)s%(message)s'))
logger.addHandler(stream_handler)
logging.getLogger('pika').setLevel(logging.WARNING)

access_point = pyaccesspoint.AccessPoint(wlan=general['wlan_if_name'], ssid=general['wlan_ssid_name'],
                                         password=general['wlan_password'], ip=general['wlan_ap_ip'],
                                         netmask=general['wlan_netmask'], inet=general['eth_if_name'])
connections = []

fec_list = []
current_fec_state = FEC(20, 30, 54)
my_fec_id = -1

vnf_list = []

stop = False

control_socket = socket.socket()
rabbit_conn = pika.BlockingConnection(
    pika.ConnectionParameters(general['control_ip'], credentials=pika.PlainCredentials(general['control_username'],
                                                                                       general['control_password'])))


def get_data_by_console(data_type, message):
    valid = False
    output = None
    if data_type == int:
        while not valid:
            try:
                output = int(input(message))
                valid = True
            except ValueError:
                logger.warning('[!] Error in introduced data! Must be int values. Try again...')
            except Exception as e:
                logger.warning('[!] Unexpected error ' + str(e) + '! Try again...')
    else:
        logger.error('[!] Data type getter not implemented!')
    return output


def listen_new_conn():
    while not stop:
        try:
            output = subprocess.check_output("iw dev wlan0 station dump | grep Station", shell=True).decode()
            macs = []
            for line in output.split('\n'):
                if line != '':
                    macs.append(line.split()[1])
            for mac in macs:
                if not check_auth(mac):
                    wait_auth_thread = threading.Thread(target=manage_new_conn, args=(mac,))
                    wait_auth_thread.daemon = True
                    wait_auth_thread.start()
            time.sleep(12)
        except KeyboardInterrupt:
            pass
        except subprocess.CalledProcessError:
            logger.debug('[D] No users connected')
            time.sleep(12)
        except Exception as e:
            logger.exception(e)


def check_auth(mac):
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
    if not check_auth(mac):
        logger.warning('[!] MAC ' + mac + ' not found. Disconnecting user...')
        os.system('sudo hostapd_cli -i wlan0 -p /tmp/hostapd disassociate ' + mac)  # Disconnect in case of not auth
    else:
        logger.info('[I] MAC ' + mac + ' authenticated. Access granted.')


def serve_client(sock, ip):
    global current_fec_state
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
                    send_fec_message()
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
                    if json_data['data']['ram'] > current_fec_state.ram or \
                            json_data['data']['gpu'] > current_fec_state.gpu or \
                            json_data['data']['bw'] > current_fec_state.bw:
                        sock.send(json.dumps(dict(res=403)).encode())  # Asked for unavailable resources
                    elif json_data['data']['target'] < 1 or json_data['data']['target'] > int(locations['max_point']):
                        sock.send(json.dumps(dict(res=404)).encode())  # Asked for non-existent target
                    else:
                        # state_vector = dict(source=json_data['data']['source'], target=json_data['data']['target'],
                        #                     gpu=json_data['data']['gpu'], ram=json_data['data']['ram'],
                        #                     bw=json_data['data']['bw'],
                        #                     previous_node=json_data['data']['previous_node'],
                        #                     current_node=json_data['data']['current_node'],
                        #                     fec_linked=json_data['data']['fec_linked'], fec_a_res=fec_list[0],
                        #                     fec_b_res=fec_list[1])
                        # logger.debug('[D] State vector to send to Model plane: ' + str(state_vector))
                        # MODEL PLANE: GET ACTION
                        if json_data['data']['target'] > json_data['data']['current_node']:
                            action = 'r'
                        else:
                            action = 'l'

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
                                sock.send(json.dumps(dict(res=404)).encode())
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
                                send_fec_message()
                                if locations is not None:
                                    next_node = get_next_node(json_data['data']['current_node'], action)
                                    sock.send(json.dumps(dict(res=200, action=action, next_node=next_node,
                                                              location=locations['point_'
                                                                                 + str(next_node)])).encode())
                                else:
                                    sock.send(json.dumps(dict(res=200, action=action)).encode())
                        else:
                            sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error from Control
                else:
                    # REACHED DESTINATION. NO NEED TO USE MODEL PLANE
                    action = 'e'
                    i = 0
                    while i < len(connections):
                        if connections[i].sock == sock:
                            break
                        else:
                            i += 1
                    if i == len(connections):
                        logger.error('[!] Trying to release resources from unknown user!')
                        sock.send(json.dumps(dict(res=404)).encode())
                    else:
                        m = 0
                        while m < len(vnf_list):
                            if json_data['data']['user_id'] == vnf_list[m]['user_id']:
                                break
                            else:
                                m += 1
                        if m != len(vnf_list):
                            logger.info('[I] Releasing resources from ' + ip + '...')

                            j = 0
                            while j < len(vnf_list):
                                if vnf_list[j]['user_id'] == connections[i].user_id:
                                    break
                                else:
                                    j += 1
                            current_fec_state.ram += vnf_list[j]['ram']
                            current_fec_state.gpu += vnf_list[j]['gpu']
                            current_fec_state.bw += vnf_list[j]['bw']
                            send_fec_message()
                        if locations is not None:
                            next_node = json_data['data']['current_node']
                            sock.send(json.dumps(dict(res=200, action=action, next_node=next_node,
                                                      location=locations['point_' + str(next_node)])).encode())
                        else:
                            sock.send(json.dumps(dict(res=200, action=action)).encode())
            except ValueError:
                sock.send(json.dumps(dict(res=400)).encode())  # Wrong query format
            except IndexError:
                sock.send(json.dumps(dict(res=500)).encode())  # Service not available (only one FEC active)
        elif json_data['type'] == 'state':
            try:
                n = 0
                while n < len(vnf_list):
                    if vnf_list[n]['user_id'] == json_data['data']['user_id']:
                        break
                    else:
                        n += 1
                if n == len(vnf_list):
                    logger.warning('[!] User tried to update a non existing VNF!')
                    sock.send(json.dumps(dict(res=404)).encode())  # User does not have active VNFs
                else:
                    vnf_list[n]['previous_node'] = json_data['data']['previous_node']
                    vnf_list[n]['current_node'] = json_data['data']['current_node']
                    vnf_list[n]['fec_linked'] = json_data['data']['fec_linked']
                    if vnf_list[n]['target'] != json_data['data']['current_node']:
                        # state_vector = dict(source=json_data['data']['source'], target=json_data['data']['target'],
                        #                     gpu=json_data['data']['gpu'], ram=json_data['data']['ram'],
                        #                     bw=json_data['data']['bw'],
                        #                     previous_node=json_data['data']['previous_node'],
                        #                     current_node=json_data['data']['current_node'],
                        #                     fec_linked=json_data['data']['fec_linked'], fec_a_res=fec_list[0],
                        #                     fec_b_res=fec_list[1])
                        # logger.debug('[D] State vector to send to Model plane: ' + str(state_vector))
                        # MODEL PLANE: GET ACTION
                        if vnf_list[n]['target'] > json_data['data']['current_node']:
                            action = 'r'
                        else:
                            action = 'l'

                        control_socket.send(json.dumps(dict(type="vnf", data=vnf_list[n])).encode())
                        control_response = json.loads(control_socket.recv(1024).decode())
                        if control_response['res'] == 200:
                            if locations is not None:
                                next_node = get_next_node(json_data['data']['current_node'], action)
                                sock.send(json.dumps(dict(res=200, action=action, next_node=next_node,
                                                          location=locations['point_'
                                                                             + str(next_node)])).encode())
                            else:
                                next_node = get_next_node(json_data['data']['current_node'], action)
                                sock.send(json.dumps(dict(res=200, action=action, next_node=next_node)).encode())
                        else:
                            sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error from Control
                    else:
                        # REACHED DESTINATION. NO NEED TO USE MODEL PLANE
                        action = 'e'
                        i = 0
                        while i < len(connections):
                            if connections[i].sock == sock:
                                break
                            else:
                                i += 1
                        if i == len(connections):
                            logger.error('[!] Trying to release resources from unknown user!')
                            sock.send(json.dumps(dict(res=404)).encode())
                        else:
                            m = 0
                            while m < len(vnf_list):
                                if json_data['data']['user_id'] == vnf_list[m]['user_id']:
                                    break
                                else:
                                    m += 1
                            if m != len(vnf_list):
                                logger.info('[I] Releasing resources from ' + ip + '...')

                                j = 0
                                while j < len(vnf_list):
                                    if vnf_list[j]['user_id'] == connections[i].user_id:
                                        break
                                    else:
                                        j += 1
                                current_fec_state.ram += vnf_list[j]['ram']
                                current_fec_state.gpu += vnf_list[j]['gpu']
                                current_fec_state.bw += vnf_list[j]['bw']
                                send_fec_message()
                            control_socket.send(json.dumps(dict(type="vnf", data=vnf_list[n])).encode())
                            control_response = json.loads(control_socket.recv(1024).decode())
                            if control_response['res'] == 200:
                                if locations is not None:
                                    next_node = json_data['data']['current_node']
                                    sock.send(json.dumps(dict(res=200, action=action, next_node=next_node,
                                                              location=locations['point_' + str(next_node)])).encode())
                                else:
                                    next_node = json_data['data']['current_node']
                                    sock.send(json.dumps(dict(res=200, action=action, next_node=next_node)).encode())
                            else:
                                sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error from Control
            except ValueError:
                sock.send(json.dumps(dict(res=400)).encode())  # Wrong query format
            except IndexError:
                sock.send(json.dumps(dict(res=500)).encode())  # Service not available (only one FEC active)
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
        send_fec_message()
        connections.pop(i)
    else:
        logger.error('[!] Disconnected unknown valid user!')
    sock.close()  # Close the connection


def send_fec_message():
    global current_fec_state
    logger.info('[I] New current FEC state! Sending to control...')
    control_socket.send(json.dumps(dict(type="fec", data=current_fec_state.__dict__)).encode())
    response = json.loads(control_socket.recv(1024).decode())
    if response['res'] != 200:
        logger.error('[!] Error from Control:' + response['res'])


def subscribe(conn, key_string):
    channel = conn.channel()

    channel.exchange_declare(exchange=general['control_exchange_name'], exchange_type='direct')

    queue = channel.queue_declare(queue='', exclusive=True).method.queue

    keys = key_string.split(' ')
    for key in keys:
        channel.queue_bind(
            exchange=general['control_exchange_name'], queue=queue, routing_key=key)

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


subscribe_thread = threading.Thread(target=subscribe, args=(rabbit_conn, 'fec vnf'))


def get_next_node(current_location, action):
    if scenario_if == 1 or scenario_if == 2:
        if action == 'r':
            return current_location + 1
        elif action == 'l':
            return current_location - 1
        else:
            return -1
    elif scenario_if == 3 or scenario_if == 5:
        if action == 'r':
            return current_location + 3
        elif action == 'l':
            return current_location - 3
        elif action == 'u':
            return current_location - 2
        elif action == 'd':
            return current_location + 2
        else:
            return -1
    elif scenario_if == 4 or scenario_if == 6:
        if action == 'r':
            return current_location + 1
        elif action == 'l':
            return current_location - 1
        elif action == 'u':
            return current_location - 4
        elif action == 'd':
            return current_location + 4
        else:
            return -1
    else:
        return -1


def kill_thread(thread_id):
    killed_threads = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), ctypes.py_object(SystemExit))
    if killed_threads == 0:
        raise ValueError("Thread ID " + str(thread_id) + " does not exist!")
    elif killed_threads > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
    logger.debug('[D] Successfully killed thread ' + str(thread_id))


def stop_program(wireshark_if, tshark_if):
    if wireshark_if == "y" or wireshark_if == "":
        os.system("sudo screen -S ap-wireshark -X stuff '^C\n'")
    if tshark_if == "y" or tshark_if == "":
        os.system("sudo screen -S ap-tshark -X stuff '^C\n'")


def main():
    global current_fec_state
    global locations
    global scenario_if
    tshark_if = 'n'
    wireshark_if = 'n'
    try:
        script_path = os.path.dirname(os.path.realpath(__file__))
        script_path = script_path + "/"
        os.system("sudo mkdir " + script_path + "logs > /dev/null 2>&1")
        os.system("sudo chmod 777 " + script_path + "logs")
        # UPDATE QUESTION
        update = input("[?] Install/Update dependencies? Y/n: (n) ")
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
            os.system("sudo apt-get install libpcap-dev -y")
            os.system("sudo python -m pip install colorlog pika configparser")
        # /UPDATE QUESTION

        # WIRESHARK & TSHARK QUESTION
        wireshark_if = input("[?] Start WIRESHARK on " + general['wlan_if_name'] + "? Y/n: (Y) ")
        wireshark_if = wireshark_if.lower()
        if wireshark_if != "y" and wireshark_if != "":
            tshark_if = input("[?] Capture packets to .pcap with TSHARK? (no gui needed) Y/n: (Y) ")
            tshark_if = tshark_if.lower()
        # /WIRESHARK & TSHARK QUESTION

        # RESOURCES QUESTION
        resources_if = input("[?] Use real available resources? Y/n: (n) ")
        if resources_if == 'Y' or resources_if == 'y':
            # GET CURRENT AVAILABLE RESOURCES
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            if device.type == 'cuda':
                gpu = int(torch.cuda.mem_get_info()[0] / (1024 ** 3))
            else:
                logger.warning('[!] CUDA device not found! Using fake value...')
                gpu = 20
            ram = int(psutil.virtual_memory().free / (1024 ** 3))
            bw = 54
            current_fec_state = FEC(gpu, ram, bw)
        # /RESOURCES QUESTION

        # SCENARIO QUESTION
        scenario_if = get_data_by_console(int, "[*] Choose which scenario to use (0 = No GPS use, 1 = 2_2, 2 = 2_4, "
                                               "3 = 2_7d, 4 = 2_8, 5 = 4_12d, 6 = 4_16): (0) ")
        if scenario_if == 1:
            logger.info('[I] Chose scenario: 2_2')
            locations = config['2_2']
        elif scenario_if == 2:
            logger.info('[I] Chose scenario: 2_4')
            locations = config['2_4']
        elif scenario_if == 3:
            logger.info('[I] Chose scenario: 2_7d')
            locations = config['2_7d']
        elif scenario_if == 4:
            logger.info('[I] Chose scenario: 2_8')
            locations = config['2_8']
        elif scenario_if == 5:
            logger.info('[I] Chose scenario: 4_12d')
            locations = config['4_12d']
        elif scenario_if == 6:
            logger.info('[I] Chose scenario: 4_16')
            locations = config['4_16']
        else:
            locations = None
        # /SCENARIO QUESTION

        # START AP
        logger.info("[I] Starting AP on " + general['wlan_if_name'] + "...")
        access_point.start()
        if wireshark_if == "y" or wireshark_if == "":
            logger.info("[I] Starting Wireshark...")
            os.system("sudo screen -S ap-wireshark -m -d wireshark -i " + general['wlan_if_name'] + " -k -w "
                      + script_path + "logs/ap-wireshark.pcap")
        if tshark_if == "y" or tshark_if == "":
            logger.info("[I] Starting Tshark...")
            os.system("sudo screen -S ap-tshark -m -d tshark -i " + general['wlan_if_name'] + " -w " + script_path +
                      "logs/ap-tshark.pcap")
        # /START AP

        time.sleep(5)

        global stop
        stop = False
        new_conn_thread = threading.Thread(target=listen_new_conn)
        new_conn_thread.daemon = True
        new_conn_thread.start()

        # Server's IP and port
        host = general['wlan_ap_ip']
        port = int(general['server_port'])

        server_socket = socket.socket()  # Create socket
        server_socket.bind((host, port))  # Bind IP address and port together

        # Configure how many client the server can listen simultaneously
        server_socket.listen(1)

        global my_fec_id

        subscribe_thread.daemon = True
        subscribe_thread.start()

        host = general['control_ip']
        port = int(general['control_port'])

        control_socket.connect((host, port))

        control_socket.send(json.dumps(dict(type="id", ip=general['my_ip'])).encode())
        response = json.loads(control_socket.recv(1024).decode())
        if response['res'] == 200:
            logger.info('[I] My ID is: ' + str(response['id']))
            my_fec_id = response['id']
        else:
            logger.critical('[!] Error from Control' + response['res'])
            raise Exception
        send_fec_message()

        # Infinite loop listening for new connections
        while True:
            conn, address = server_socket.accept()  # Accept new connection
            logger.info("[I] New connection from: " + str(address))
            socket_thread = threading.Thread(target=serve_client, args=(conn, address[0]))
            socket_thread.daemon = True
            socket_thread.start()
    except KeyboardInterrupt:
        logger.info("[!] Stopping... (Dont worry if you get errors)")
        stop = True
        kill_thread(subscribe_thread.ident)
        subscribe_thread.join()
        rabbit_conn.close()
        control_socket.close()
        for connection in connections:
            connection.sock.close()
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        logger.info("[I] AP stopped.")
    except OSError:
        logger.critical("[!] Error when binding address and port for server! Stopping...")
        stop = True
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        logger.info("[I] AP stopped.")
    except TypeError:
        logger.critical("[!] Detected error in value type at one variable! Stopping...")
        stop = True
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        logger.info("[I] AP stopped.")
    except ValueError:
        logger.critical("[!] Detected error in value at one variable! Stopping...")
        stop = True
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        logger.info("[I] AP stopped.")
    except Exception as e:
        logger.exception(e)
        stop = True
        access_point.stop()
        stop_program(wireshark_if, tshark_if)
        logger.info("[I] AP stopped.")


if __name__ == '__main__':
    main()
