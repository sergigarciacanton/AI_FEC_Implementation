from pyaccesspoint.PyAccessPoint import pyaccesspoint
import socket
import time
import threading
import subprocess
import os


access_point = pyaccesspoint.AccessPoint(wlan='wlan0', ssid='Test301', password='1234567890',
                                         ip='10.0.0.1', netmask='255.255.255.0', inet='eth0')
connections = []
valid_ids = [1, 2, 3]


class Connection:
    def __init__(self, conn_id, sock, mac, ip):
        self.conn_id = conn_id
        self.sock = sock
        self.mac = mac
        self.ip = ip

    def __str__(self):
        return f"User ID: {self.conn_id} | Socket ID: {self.sock} | MAC: {self.mac} | IP: {self.ip}"


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


def serve_client(conn, ip):
    while True:
        if stop:
            break
        data = conn.recv(1024).decode()  # Receive data stream. it won't accept data packet greater than 1024 bytes
        if not data:
            break  # If data is not received break

        print("[I] From connected user: " + str(data))
        split = data.split('/')

        if split[0] == '0':  # Finish setting up connection. Format: '0/{usr_id}'
            try:
                if valid_ids.index(int(split[1])) >= 0:
                    connections.append(Connection(int(split[1]),
                                                  conn,
                                                  subprocess.check_output(['arp', '-n', ip]).decode().split('\n')[
                                                      1].split()[2],
                                                  ip))
                    conn.send('0/0'.encode())  # Access granted
            except ValueError:
                conn.send('0/1'.encode())  # Wrong query

        else:
            conn.send('-1'.encode())

    found = False
    i = 0
    while not found and i < len(connections):
        if connections[i].conn_id == conn:
            found = True
        else:
            i += 1
    if found:
        connections.pop(i)
    conn.close()  # Close the connection


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
