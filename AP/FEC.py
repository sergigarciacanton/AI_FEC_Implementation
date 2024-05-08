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
import fcntl
import struct
import copy
from typing import Optional
from config import TIMESTEPS_LIMIT, FECS_RANGE, \
    EDGES_COST, NODES_POSITION, \
    MAX_GPU, MIN_GPU, MIN_RAM, \
    MAX_RAM, MIN_BW, MAX_BW
from prometheus_client import start_http_server, Gauge


def get_next_hop_fec(cav_trajectory) -> Optional[int]:
    """
    Retrieves the FEC associated with the last hop in the given CAV trajectory.

    Parameters:
    - cav_trajectory (Tuple[int, int]): The CAV trajectory represented as a tuple of current and previous nodes.

    Returns: - Optional[int]: The FEC (Forward Error Correction) associated with the last hop, or None if no matching
    FEC is found.
    """

    try:
        return next((fec for fec, one_hop_path in FECS_RANGE.items() if cav_trajectory in one_hop_path))
    except StopIteration:
        logger.error(str(cav_trajectory))
        raise ValueError("No matching FEC found for the given CAV trajectory.")


class FEC:
    def __init__(self, gpu, ram, bw, access_point, rabbit_conn, locations):
        self.id = None
        self.ip = None
        self.current_state = {"gpu": gpu, "ram": ram, "bw": bw, "mac": self.get_mac_address(general['wlan_if_name']),
                              "connected_users": []}
        self.control_socket = socket.socket()
        self.connections = dict()
        self.fec_list = dict()
        self.vnf_list = dict()
        self.access_point = access_point
        self.rabbit_conn = rabbit_conn
        self.subscribe_thread = threading.Thread(target=self.subscribe, args=(self.rabbit_conn, 'fec vnf'))
        self.update_thread = threading.Thread(target=self.update_prometheus)
        self.network_thread = threading.Thread(target=self.network_usage)
        self.locations = locations
        self.next_action = None
        self.run_fec(general['wireshark_if'], general['tshark_if'], general['resources_if'])

    def get_mac_address(self, if_name):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(if_name, 'utf-8')[:15]))
        return ':'.join('%02x' % b for b in info[18:24])

    def get_data_by_console(self, data_type, message):
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

    def agent_conn(self):
        host = self.control_socket.getsockname()[0]
        port = int(general['agent_port'])

        server_socket = socket.socket()  # Create socket
        server_socket.bind((host, port))  # Bind IP address and port together

        # Configure how many client the server can listen simultaneously
        server_socket.listen(1)

        # Infinite loop listening for new connections
        while True:
            conn, address = server_socket.accept()  # Accept new connection
            while True:
                if stop:
                    break
                data = conn.recv(
                    1024).decode()  # Receive data stream. it won't accept data packet greater than 1024 bytes
                if not data:
                    break  # If data is not received break

                logger.info("[I] From agent " + str(address) + ": " + str(data))
                json_data = json.loads(data)

                if json_data[
                    'type'] == 'action':  # Finish setting up connection. Format: {"type": "auth", "user_id": 1}
                    try:
                        self.next_action = json_data['action']
                        conn.send(json.dumps(dict(res=200, id=self.id)).encode())  # Action saved
                    except ValueError:
                        logger.error('[!] ValueError when receiving action from agent: json_data = ' + str(json_data))
                        conn.send(json.dumps(dict(res=404)).encode())  # Wrong query format
                else:
                    conn.send(json.dumps(dict(res=400)).encode())  # Bad request
            conn.close()  # Close the connection

    def listen_new_conn(self):
        while not stop:
            try:
                output = subprocess.check_output("iw dev wlan0 station dump | grep Station", shell=True).decode()
                macs = []
                for line in output.split('\n'):
                    if line != '':
                        macs.append(line.split()[1])
                for mac in macs:
                    if not self.check_auth(mac):
                        wait_auth_thread = threading.Thread(target=self.manage_new_conn, args=(mac,))
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

    def check_auth(self, mac):
        i = 0
        found = False
        while not found and i < len(self.connections):
            if self.connections[i]['mac'] == str(mac):
                found = True
            else:
                i += 1
        return found

    def manage_new_conn(self, mac):
        logger.info('[I] MAC ' + mac + ' just connected. Waiting for auth...')
        time.sleep(10)
        try:
            if not self.check_auth(mac):
                output = subprocess.check_output("iw dev wlan0 station dump | grep Station", shell=True).decode()
                macs = []
                for line in output.split('\n'):
                    if line != '':
                        macs.append(line.split()[1])
                for conn_mac in macs:
                    if mac == conn_mac:
                        logger.warning('[!] MAC ' + mac + ' not found. Disconnecting user...')
                        os.system(
                            'sudo hostapd_cli -i wlan0 -p /tmp/hostapd disassociate ' + mac)  # Not auth. Disconnect
                        break
            else:
                logger.info('[I] MAC ' + mac + ' authenticated. Access granted.')  # Auth successful
        except subprocess.CalledProcessError:
            logger.debug('[D] No users connected')

    def get_action(self, target, curr_node):
        scenario_if = int(general['scenario_if'])
        if scenario_if == 3:
            if curr_node == 1:
                if target != 3 and target != 6:
                    return 4
                else:
                    return 5
            elif curr_node == 2:
                if target == 5 or target == 7:
                    return 5
                else:
                    return 4
            elif curr_node == 3:
                if target != 1:
                    return 6
                else:
                    return 1
            elif curr_node == 4:
                if target == 6:
                    return 6
                elif target == 2:
                    return 2
                elif target == 1 or target == 3:
                    return 1
                else:
                    return 7
            elif curr_node == 5:
                if target != 7:
                    return 2
                else:
                    return 7
            elif curr_node == 6:
                if target == 1 or target == 3:
                    return 3
                else:
                    return 4
            elif curr_node == 7:
                if target == 2 or target == 5:
                    return 5
                else:
                    return 4
        elif scenario_if == 4:
            if curr_node == 1:
                if target != 5:
                    return 2
                else:
                    return 5
            elif curr_node == 2:
                if target == 6:
                    return 6
                elif target == 1 or target == 5:
                    return 1
                else:
                    return 3
            elif curr_node == 3:
                if target == 7:
                    return 7
                elif target == 4 or target == 8:
                    return 4
                else:
                    return 2
            elif curr_node == 4:
                if target != 8:
                    return 8
                else:
                    return 3
            elif curr_node == 5:
                if target != 1:
                    return 6
                else:
                    return 1
            elif curr_node == 6:
                if target == 2:
                    return 2
                elif target == 1 or target == 5:
                    return 5
                else:
                    return 7
            elif curr_node == 7:
                if target == 3:
                    return 3
                elif target == 4 or target == 8:
                    return 8
                else:
                    return 6
            elif curr_node == 8:
                if target != 4:
                    return 7
                else:
                    return 4
        elif scenario_if == 5:
            if curr_node == 1:
                if target != 3 and target != 6 and target != 8 and target != 11:
                    return 4
                else:
                    return 3
            elif curr_node == 2:
                if target == 5 or target == 7 or target == 10 or target == 12:
                    return 5
                else:
                    return 4
            elif curr_node == 3:
                if target != 1:
                    return 6
                else:
                    return 1
            elif curr_node == 4:
                if target == 6 or target == 8 or target == 9 or target == 11:
                    return 6
                elif target == 2:
                    return 2
                elif target == 1 or target == 3:
                    return 1
                else:
                    return 7
            elif curr_node == 5:
                if target != 7 and target != 9 and target != 10 and target != 11 and target != 12:
                    return 2
                else:
                    return 7
            elif curr_node == 6:
                if target == 1 or target == 3:
                    return 3
                elif target == 8 or target == 11:
                    return 8
                elif target == 2 or target == 4 or target == 5:
                    return 5
                else:
                    return 9
            elif curr_node == 7:
                if target == 2 or target == 5:
                    return 5
                elif target == 10 or target == 14:
                    return 10
                elif target == 8 or target == 9 or target == 11:
                    return 9
                else:
                    return 4
            elif curr_node == 8:
                if target != 9 and target != 10 and target != 11 and target != 12:
                    return 5
                else:
                    return 11
            elif curr_node == 9:
                if target == 2 or target == 4 or target == 5 or target == 7:
                    return 7
                elif target == 11:
                    return 11
                elif target == 10 or target == 12:
                    return 12
                else:
                    return 6
            elif curr_node == 10:
                if target != 12:
                    return 5
                else:
                    return 12
            elif curr_node == 11:
                if target == 8:
                    return 8
                else:
                    return 9
            elif curr_node == 12:
                if target == 1 or target == 2 or target == 4 or target == 5 or target == 7 or target == 10:
                    return 10
                else:
                    return 9
        elif scenario_if == 6:
            if curr_node == 0:
                return 4
            elif curr_node == 1:
                return 0
            elif curr_node == 2:
                if target == 0 or target == 1 or target == 4 or target == 5:
                    return 1
                else:
                    return 6
            elif curr_node == 3:
                return 2
            elif curr_node == 4:
                if target == 8 or target == 9 or target == 12 or target == 13:
                    return 8
                else:
                    return 5
            elif curr_node == 5:
                if target == 0 or target == 1 or target == 4 or target == 8 or target == 12 or target == 13:
                    return 1
                else:
                    return 6
            elif curr_node == 6:
                if target == 0 or target == 1 or target == 2 or target == 3 or target == 4 or target == 7:
                    return 7
                else:
                    return 10
            elif curr_node == 7:
                return 3
            elif curr_node == 8:
                return 12
            elif curr_node == 9:
                if target == 8 or target == 11 or target == 12 or target == 13 or target == 14 or target == 15:
                    return 8
                else:
                    return 5
            elif curr_node == 10:
                if target == 2 or target == 3 or target == 7 or target == 11 or target == 14 or target == 15:
                    return 14
                else:
                    return 9
            elif curr_node == 11:
                if target == 2 or target == 3 or target == 6 or target == 7:
                    return 7
                else:
                    return 10
            elif curr_node == 12:
                return 13
            elif curr_node == 13:
                if target == 10 or target == 11 or target == 14 or target == 15:
                    return 14
                else:
                    return 9
            elif curr_node == 14:
                return 15
            elif curr_node == 15:
                return 11
        elif scenario_if == 7:
            if curr_node < 5:
                if target > curr_node:
                    return curr_node + 1
                else:
                    return curr_node - 1
            elif curr_node == 5:
                if target > 5:
                    return 6
                else:
                    return 4
            elif curr_node == 6:
                if target > 6:
                    return 7
                else:
                    return 5
            elif curr_node == 7:
                if target > 7:
                    return 8
                else:
                    return 6
            elif curr_node > 7:
                if target > curr_node:
                    return curr_node + 1
                else:
                    return curr_node - 1
        else:
            if target > curr_node:
                return curr_node + 1
            else:
                return curr_node - 1

    def serve_client(self, sock, ip):
        user_id = None
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
                    self.control_socket.send(json.dumps(dict(type="auth", user_id=json_data['user_id'])).encode())
                    control_response = json.loads(self.control_socket.recv(1024).decode())
                    if control_response['res'] == 200:
                        if general['training_if'] != 'y' and general['training_if'] != 'Y':
                            self.connections[str(json_data['user_id'])] = {"sock": sock,
                                                                           "mac": subprocess.check_output(
                                                                               ['arp', '-n', ip]).decode() \
                                                                               .split('\n')[1].split()[2],
                                                                           "ip": ip}

                        else:
                            self.connections[str(json_data['user_id'])] = {"sock": sock, "ip": ip}
                        user_id = str(json_data['user_id'])
                        self.current_state['connected_users'].append(json_data['user_id'])
                        if str(json_data['user_id']) in self.vnf_list:
                            logger.info('[I] Assigning resources for ' + ip + '...')
                            self.current_state['ram'] -= self.vnf_list[user_id]['ram']
                            self.current_state['gpu'] -= self.vnf_list[user_id]['gpu']
                            self.current_state['bw'] -= self.vnf_list[user_id]['bw']
                        self.send_fec_message()
                        if self.id == -1:
                            logger.error('[!] FEC not connected to control!')
                            sock.send(json.dumps(dict(res=500)).encode())  # FEC not connected to Control
                        else:
                            sock.send(json.dumps(dict(res=200, id=self.id)).encode())  # Access granted
                    else:
                        logger.error('[!] Error from control when authenticating a CAV: ' + str(control_response))
                        sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error reported by Control
                except ValueError as e:
                    logger.error('[!] ValueError at FEC when assigning resources during auth: ' + str(e))
                    sock.send(json.dumps(dict(res=404)).encode())  # Wrong query format
            elif json_data['type'] == 'vnf':
                try:
                    if json_data['data']['target'] != json_data['data']['current_node']:
                        if json_data['data']['ram'] > self.current_state['ram'] or \
                                json_data['data']['gpu'] > self.current_state['gpu'] or \
                                json_data['data']['bw'] > self.current_state['bw']:
                            sock.send(json.dumps(dict(res=403)).encode())  # Asked for unavailable resources
                        elif json_data['data']['target'] < 0 or json_data['data']['target'] > int(
                                self.locations['max_point']):
                            logger.error('[!] Error: target does not exist! json_data = ' + str(json_data))
                            sock.send(json.dumps(dict(res=404)).encode())  # Asked for non-existent target
                        else:
                            self.control_socket.send(json.dumps(dict(type="vnf", user_id=json_data['user_id'],
                                                                     data=json_data['data'])).encode())
                            control_response = json.loads(self.control_socket.recv(1024).decode())
                            if control_response['res'] == 200:
                                if user_id not in self.connections:
                                    logger.error('[!] Trying to assign resources to unknown user!')
                                    sock.send(json.dumps(dict(res=404)).encode())
                                else:
                                    # MODEL PLANE: GET ACTION
                                    if general['agent_if'] == 'y' or general['agent_if'] == 'Y':
                                        while self.next_action is None:
                                            time.sleep(0.001)
                                        next_node = self.next_action
                                        self.next_action = None
                                    else:
                                        next_node = self.get_action(json_data['data']['target'],
                                                                    json_data['data']['current_node'])
                                    next_cav_trajectory = (json_data['data']['current_node'], next_node)
                                    cav_fec = get_next_hop_fec(next_cav_trajectory)
                                    # cav_fec = int(self.locations['point_' + str(json_data['data']['current_node'])
                                    #                         + '_' + str(next_node)])
                                    if cav_fec == self.id:
                                        logger.info('[I] Assigning resources for ' + ip + '...')
                                        self.current_state['ram'] -= json_data['data']['ram']
                                        self.current_state['gpu'] -= json_data['data']['gpu']
                                        self.current_state['bw'] -= json_data['data']['bw']
                                    self.send_fec_message()

                                    if general['training_if'] != 'y' and general['training_if'] != 'Y':
                                        if self.locations is not None:
                                            fec_mac = self.fec_list[str(cav_fec)]['mac']
                                            sock.send(json.dumps(dict(res=200, next_node=next_node,
                                                                      cav_fec=cav_fec, fec_mac=fec_mac,
                                                                      location=self.locations['point_'
                                                                                              + str(
                                                                          next_node)])).encode())
                                        else:
                                            sock.send(json.dumps(dict(res=200, next_node=next_node)).encode())
                                    else:
                                        if self.locations is not None:
                                            fec_ip = self.fec_list[str(cav_fec)]['ip']
                                            sock.send(json.dumps(dict(res=200, next_node=next_node,
                                                                      cav_fec=cav_fec, fec_ip=fec_ip,
                                                                      location=self.locations['point_'
                                                                                              + str(
                                                                          next_node)])).encode())
                                        else:
                                            sock.send(json.dumps(dict(res=200, next_node=next_node)).encode())
                            else:
                                logger.error('[!] Error from control: ' + str(control_response['res']))
                                sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error from Control
                    else:
                        # REACHED DESTINATION. NO NEED TO USE MODEL PLANE
                        if user_id not in self.connections:
                            logger.error('[!] Trying to release resources from unknown user!')
                            sock.send(json.dumps(dict(res=404)).encode())
                        else:
                            self.current_state['ram'] += self.vnf_list[user_id]['ram']
                            self.current_state['gpu'] += self.vnf_list[user_id]['gpu']
                            self.current_state['bw'] += self.vnf_list[user_id]['bw']
                            self.send_fec_message()

                            sock.send(json.dumps(dict(res=200, next_node=-1)).encode())
                except ValueError as e:
                    logger.error('[!] ValueError at FEC when receiving VNF: ' + str(e))
                    sock.send(json.dumps(dict(res=400)).encode())  # Wrong query format
                except IndexError as e:
                    logger.error('[!] IndexError at FEC when receiving VNF: ' + str(e) + '. vnf_list = '
                                 + str(self.vnf_list) + '. connections = ' + str(self.connections) + '. json_data = '
                                 + str(json_data) + '. fec_list = ' + str(self.fec_list))
                    sock.send(json.dumps(dict(res=500)).encode())  # Service not available (only one FEC active)
            elif json_data['type'] == 'state':
                try:
                    self.vnf_list[user_id]['previous_node'] = json_data['data']['previous_node']
                    self.vnf_list[user_id]['current_node'] = json_data['data']['current_node']
                    self.vnf_list[user_id]['cav_fec'] = json_data['data']['cav_fec']
                    self.vnf_list[user_id]['time_steps'] = json_data['data']['time_steps']
                    if self.vnf_list[user_id]['target'] != json_data['data']['current_node']:
                        self.send_fec_message()
                        self.control_socket.send(json.dumps(dict(type="vnf", user_id=user_id,
                                                                 data=self.vnf_list[user_id])).encode())
                        control_response = json.loads(self.control_socket.recv(1024).decode())
                        if control_response['res'] == 200:
                            if self.locations is not None:
                                # MODEL PLANE: GET ACTION
                                if general['agent_if'] == 'y' or general['agent_if'] == 'Y':
                                    while self.next_action is None:
                                        time.sleep(0.001)
                                    next_node = self.next_action
                                    self.next_action = None
                                else:
                                    next_node = self.get_action(self.vnf_list[user_id]['target'],
                                                                json_data['data']['current_node'])
                                if next_node is not -1:
                                    next_cav_trajectory = (json_data['data']['current_node'], next_node)
                                    cav_fec = get_next_hop_fec(next_cav_trajectory)
                                    if general['training_if'] != 'y' and general['training_if'] != 'Y':
                                        fec_mac = self.fec_list[str(cav_fec)]['mac']
                                        sock.send(json.dumps(dict(res=200, next_node=next_node,
                                                                  cav_fec=cav_fec, fec_mac=fec_mac,
                                                                  location=self.locations['point_'
                                                                                          + str(next_node)])).encode())
                                    else:
                                        fec_ip = self.fec_list[str(cav_fec)]['ip']
                                        sock.send(json.dumps(dict(res=200, next_node=next_node,
                                                                  cav_fec=cav_fec, fec_ip=fec_ip,
                                                                  location=self.locations['point_'
                                                                                          + str(next_node)])).encode())
                                else:
                                    sock.send(json.dumps(dict(res=200, next_node=-1)).encode())  # Stop CAV. Truncated
                                    vnf_to_kill = copy.deepcopy(self.vnf_list[user_id])
                                    vnf_to_kill['current_node'] = vnf_to_kill['target']
                                    self.control_socket.send(json.dumps(dict(type="vnf", user_id=int(user_id),
                                                                             data=vnf_to_kill)).encode())
                                    control_response = json.loads(self.control_socket.recv(1024).decode())
                                    if control_response['res'] != 200:
                                        logger.error('[!] Error from control: ' + str(control_response['res']))
                                        sock.send(json.dumps(
                                            dict(res=control_response['res'])).encode())  # Error from Control
                            else:
                                sock.send(json.dumps(dict(res=200, next_node=next_node)).encode())
                        else:
                            logger.error('[!] Error from control: ' + str(control_response['res']))
                            sock.send(json.dumps(dict(res=control_response['res'])).encode())  # Error from Control
                    else:
                        # REACHED DESTINATION. NO NEED TO USE MODEL PLANE
                        if user_id not in self.connections:
                            logger.error('[!] Trying to release resources from unknown user!')
                            sock.send(json.dumps(dict(res=404)).encode())
                        else:
                            if user_id in self.vnf_list:
                                logger.info('[I] Releasing resources from ' + ip + '...')
                                self.current_state['ram'] += self.vnf_list[user_id]['ram']
                                self.current_state['gpu'] += self.vnf_list[user_id]['gpu']
                                self.current_state['bw'] += self.vnf_list[user_id]['bw']
                                self.control_socket.send(json.dumps(dict(type="vnf", user_id=user_id,
                                                                         data=self.vnf_list[user_id])).encode())
                            else:
                                self.control_socket.send(json.dumps(dict(type="vnf", user_id=user_id,
                                                                         data=self.vnf_list[user_id])).encode())
                            control_response = json.loads(self.control_socket.recv(1024).decode())
                            if control_response['res'] == 200:
                                self.send_fec_message()
                                sock.send(json.dumps(dict(res=200, next_node=-1)).encode())
                            else:
                                logger.error('[!] Error from control when sending ended VNF: '
                                             + str(control_response['res']))
                                sock.send(
                                    json.dumps(dict(res=control_response['res'])).encode())  # Error from Control
                except ValueError as e:
                    logger.error('[!] ValueError at FEC when updating CAV status: ' + str(e))
                    sock.send(json.dumps(dict(res=400)).encode())  # Wrong query format
                except IndexError as e:
                    logger.error('[!] IndexError at FEC when updating CAV status: ' + str(e))
                    sock.send(json.dumps(dict(res=500)).encode())  # Service not available (only one FEC active)
            elif json_data['type'] == 'bye':  # Disconnect. Format: {"type": "bye"}
                break
            else:
                sock.send(json.dumps(dict(res=400)).encode())  # Bad request

        try:
            if user_id in self.connections:
                if user_id in self.vnf_list:
                    if self.vnf_list[user_id]['previous_node'] != self.vnf_list[user_id]['current_node'] \
                            and self.vnf_list[user_id]['current_node'] != self.vnf_list[user_id]['target']:
                        self.current_state['ram'] += self.vnf_list[user_id]['ram']
                        self.current_state['gpu'] += self.vnf_list[user_id]['gpu']
                        self.current_state['bw'] += self.vnf_list[user_id]['bw']
                        logger.info('[I] Releasing resources from ' + ip + '...')
                logger.info('[I] User ' + ip + ' disconnected.')
                self.current_state['connected_users'].remove(int(user_id))
                self.connections.pop(user_id)
                self.send_fec_message()
            else:
                logger.error('[!] Disconnected unknown valid user!')
            sock.send(json.dumps(dict(res=200)).encode())
            sock.close()  # Close the connection
        except IndexError as e:
            logger.error('[!] IndexError when disconnecting CAV from FEC: ' + str(e) + '. connections = ' + str(
                self.connections))

    def send_fec_message(self):
        logger.info('[I] New current FEC state! Sending to control...')
        self.control_socket.send(json.dumps(dict(type="fec", data=self.current_state)).encode())
        response = json.loads(self.control_socket.recv(1024).decode())
        if response['res'] != 200:
            logger.error('[!] Error from Control when sending FEC message:' + str(response['res']))

    def subscribe(self, conn, key_string):
        channel = conn.channel()

        channel.exchange_declare(exchange=general['control_exchange_name'], exchange_type='direct')

        queue = channel.queue_declare(queue='', exclusive=True).method.queue

        keys = key_string.split(' ')
        for key in keys:
            channel.queue_bind(
                exchange=general['control_exchange_name'], queue=queue, routing_key=key)

        logger.info('[I] Waiting for published data...')

        def callback(ch, method, properties, body):
            logger.debug("[D] Received message. Key: " + str(method.routing_key) + ". Message: " + body.decode("utf-8"))
            if str(method.routing_key) == 'fec':
                self.fec_list = json.loads(body.decode('utf-8'))
            elif str(method.routing_key) == 'vnf':
                self.vnf_list = json.loads(body.decode('utf-8'))

        channel.basic_consume(
            queue=queue, on_message_callback=callback, auto_ack=True)

        channel.start_consuming()

    def kill_thread(self, thread_id):
        killed_threads = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id),
                                                                    ctypes.py_object(SystemExit))
        if killed_threads == 0:
            raise ValueError("Thread ID " + str(thread_id) + " does not exist!")
        elif killed_threads > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
        logger.debug('[D] Successfully killed thread ' + str(thread_id))

    def stop_program(self, wireshark_if, tshark_if):
        if wireshark_if == "y" or wireshark_if == "":
            os.system("sudo screen -S ap-wireshark -X stuff '^C\n'")
        if tshark_if == "y" or tshark_if == "":
            os.system("sudo screen -S ap-tshark -X stuff '^C\n'")

    def run_fec(self, wireshark_if, tshark_if, resources_if):
        global stop
        try:
            script_path = os.path.dirname(os.path.realpath(__file__))
            script_path = script_path + "/"

            # WIRESHARK & TSHARK QUESTION
            wireshark_if = wireshark_if.lower()
            tshark_if = tshark_if.lower()
            # /WIRESHARK & TSHARK QUESTION

            # RESOURCES QUESTION
            if resources_if == 'Y' or resources_if == 'y':
                # GET CURRENT AVAILABLE RESOURCES
                device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
                if device.type == 'cuda':
                    self.current_state['gpu'] = int(torch.cuda.mem_get_info()[0] / (1024 ** 2))
                else:
                    logger.warning('[!] CUDA device not found! Using fake value...')
                    self.current_state['gpu'] = 20000
                self.current_state['ram'] = int(psutil.virtual_memory().free / (1024 ** 2))
                #self.current_state['bw'] = 54
                # self.current_state['bw'] = int(psutil.net_if_stats()["eth0"].speed)
            # /RESOURCES QUESTION

            # START AP

            if general['training_if'] == 'n':
                logger.warning("[I] Starting AP on " + general['wlan_if_name'] + "...")
                os.system('sudo systemctl stop systemd-resolved')
                self.access_point.start()
            if wireshark_if == "y" or wireshark_if == "":
                logger.warning("[I] Starting Wireshark...")
                if general['training_if'] == 'n':
                    os.system("sudo screen -S ap-wireshark -m -d wireshark -i " + general['wlan_if_name'] + " -k -w "
                              + script_path + "logs/ap-wireshark.pcap")
                else:
                    os.system("sudo screen -S ap-wireshark -m -d wireshark -i " + general['eth_if_name'] + " -k -w "
                              + script_path + "logs/ap-wireshark.pcap")
            if tshark_if == "y" or tshark_if == "":
                logger.warning("[I] Starting Tshark...")
                if general['training_if'] == 'n':
                    os.system(
                        "sudo screen -S ap-tshark -m -d tshark -i " + general['wlan_if_name'] + " -w " + script_path +
                        "logs/ap-tshark.pcap")
                else:
                    os.system(
                        "sudo screen -S ap-tshark -m -d tshark -i " + general['eth_if_name'] + " -w " + script_path +
                        "logs/ap-tshark.pcap")
            # /START AP

            time.sleep(5)

            stop = False

            self.subscribe_thread.daemon = True
            self.subscribe_thread.start()
            self.update_thread.daemon = True
            self.update_thread.start()
            self.network_thread.daemon = True
            self.network_thread.start()

            host = general['control_ip']
            port = int(general['control_port'])

            self.control_socket.connect((host, port))

            self.control_socket.send(json.dumps(dict(type="id", ip=self.control_socket.getsockname()[0],
                                                     mac=self.get_mac_address(general['wlan_if_name']))).encode())
            response = json.loads(self.control_socket.recv(1024).decode())
            if response['res'] == 200:
                logger.warning('[I] My ID is: ' + str(response['id']))
                self.id = response['id']
            else:
                logger.critical('[!] Error from Control' + str(response['res']))
                raise Exception
            self.send_fec_message()

            if general['agent_if'] == 'y' or general['agent_if'] == 'Y':
                agent_conn_thread = threading.Thread(target=self.agent_conn)
                agent_conn_thread.daemon = True
                agent_conn_thread.start()

            # Server's IP and port
            if general['training_if'] == 'n':
                host = general['wlan_ap_ip']
            else:
                new_conn_thread = threading.Thread(target=self.listen_new_conn)
                new_conn_thread.daemon = True
                new_conn_thread.start()
                host = self.control_socket.getsockname()[0]
            port = int(general['server_port'])

            server_socket = socket.socket()  # Create socket
            server_socket.bind((host, port))  # Bind IP address and port together

            # Configure how many client the server can listen simultaneously
            server_socket.listen(1)

            # Infinite loop listening for new connections
            while True:
                conn, address = server_socket.accept()  # Accept new connection
                logger.info("[I] New connection from: " + str(address))
                socket_thread = threading.Thread(target=self.serve_client, args=(conn, address[0]))
                socket_thread.daemon = True
                socket_thread.start()
        except KeyboardInterrupt:
            logger.warning("[!] Stopping... (Dont worry if you get errors)")
            stop = True
            self.kill_thread(self.subscribe_thread.ident)
            self.subscribe_thread.join()
            self.kill_thread(self.update_thread.ident)
            self.update_thread.join()
            self.kill_thread(self.network_thread.ident)
            self.network_thread.join()
            self.rabbit_conn.close()
            self.control_socket.close()
            for connection in self.connections.values():
                connection['sock'].close()
            if general['training_if'] == 'n':
                self.access_point.stop()
                logger.info("[I] AP stopped.")
            self.stop_program(wireshark_if, tshark_if)
            if general['training_if'] != 'n':
                time.sleep(3)
                os.system('sudo systemctl start systemd-resolved')
        except OSError as e:
            logger.critical("[!] Error when binding address and port for server! Stopping... " + str(e))
            stop = True
            if general['training_if'] == 'n':
                self.access_point.stop()
                logger.info("[I] AP stopped.")
            self.stop_program(wireshark_if, tshark_if)
            if general['training_if'] != 'n':
                time.sleep(3)
                os.system('sudo systemctl start systemd-resolved')
        except TypeError:
            logger.critical("[!] Detected error in value type at one variable! Stopping...")
            stop = True
            if general['training_if'] == 'n':
                self.access_point.stop()
                logger.info("[I] AP stopped.")
            self.stop_program(wireshark_if, tshark_if)
            if general['training_if'] != 'n':
                time.sleep(3)
                os.system('sudo systemctl start systemd-resolved')
        except ValueError:
            logger.critical("[!] Detected error in value at one variable! Stopping...")
            stop = True
            if general['training_if'] == 'n':
                self.access_point.stop()
                logger.info("[I] AP stopped.")
            self.stop_program(wireshark_if, tshark_if)
            if general['training_if'] != 'n':
                time.sleep(3)
                os.system('sudo systemctl start systemd-resolved')
        except Exception as e:
            logger.exception(e)
            stop = True
            if general['training_if'] == 'n':
                self.access_point.stop()
            self.stop_program(wireshark_if, tshark_if)
            if general['training_if'] != 'n':
                time.sleep(3)
                os.system('sudo systemctl start systemd-resolved')

    def update_prometheus(self):
        # PROMETHEUS
        while True:
            RAM.set(int(psutil.virtual_memory().free / (1024 ** 2)))
            GPU.set(int(torch.cuda.mem_get_info()[0] / (1024 ** 2)))
            BW.set(self.current_state['bw'])
            time.sleep(2)

    def network_usage(self):
        while True:
            start_time = time.time()
            init_packets = (psutil.net_io_counters(pernic=True)["eth0"].bytes_recv +
                            psutil.net_io_counters(pernic=True)["eth0"].bytes_sent)
            time.sleep(1)
            final_packets = (psutil.net_io_counters(pernic=True)["eth0"].bytes_recv +
                             psutil.net_io_counters(pernic=True)["eth0"].bytes_sent)
            end_time = time.time()
            self.current_state['bw'] = ((final_packets - init_packets) / (end_time - start_time)) * 8 / (1024 ** 2)


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("fec_annex.ini")
    general = config['general']
    locations = config['general']

    logger = logging.getLogger('')
    logger.setLevel(int(general['log_level']))
    logger.addHandler(logging.FileHandler(general['log_file_name'], mode='w', encoding='utf-8'))
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(ColoredFormatter('%(log_color)s%(message)s'))
    logger.addHandler(stream_handler)
    logging.getLogger('pika').setLevel(logging.WARNING)
    
    # PROMETHEUS
    start_http_server(addr=general['fec_eth_ip'], port=8000)
    RAM = Gauge('RAM_available', 'RAM Available in FEC1')
    GPU = Gauge('GPU_available', 'GPU Available in FEC1')
    BW = Gauge('BW_available', 'BW Available in FEC1')

    # SCENARIO QUESTION
    scenario_if = int(general['scenario_if'])
    if scenario_if == 0:
        logger.warning('[I] Chose scenario: No GPS use')
        locations = None
    elif scenario_if == 1:
        logger.warning('[I] Chose scenario: 2_2')
        locations = config['2_2']
    elif scenario_if == 2:
        logger.warning('[I] Chose scenario: 2_4')
        locations = config['2_4']
    elif scenario_if == 3:
        logger.warning('[I] Chose scenario: 2_7d')
        locations = config['2_7d']
    elif scenario_if == 4:
        logger.warning('[I] Chose scenario: 2_8')
        locations = config['2_8']
    elif scenario_if == 5:
        logger.warning('[I] Chose scenario: 4_12d')
        locations = config['4_12d']
    elif scenario_if == 6:
        logger.warning('[I] Chose scenario: 4_16')
        locations = config['4_16']
    elif scenario_if == 7:
        logger.warning('[I] Chose scenario: str')
        locations = config['str']
    else:
        logger.critical('Tried to load a non-existing scenario! Exiting...')
        exit(-1)
    # /SCENARIO QUESTION

    stop = False
    if general['training_if'] == 'n':
        my_fec = FEC(16, 32, 64, pyaccesspoint.AccessPoint(wlan=general['wlan_if_name'], ssid=general['wlan_ssid_name'],
                                                           password=general['wlan_password'], ip=general['wlan_ap_ip'],
                                                           netmask=general['wlan_netmask'],
                                                           inet=general['eth_if_name']), pika.BlockingConnection(
            pika.ConnectionParameters(host=general['control_ip'], port=int(general['rabbit_port']),
                                      credentials=pika.PlainCredentials(general['control_username'],
                                                                        general['control_password']))), locations)
    else:
        my_fec = FEC(16, 32, 64, None, pika.BlockingConnection(
            pika.ConnectionParameters(host=general['control_ip'], port=int(general['rabbit_port']),
                                      credentials=pika.PlainCredentials(general['control_username'],
                                                                        general['control_password']))), locations)
