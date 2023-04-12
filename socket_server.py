import socket
import time
import threading
import subprocess
import os


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
        if connections[i].hd == str(mac):
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


class Connection:
    def __init__(self, conn_id, sock, mac, ip):
        self.conn_id = conn_id
        self.sock = sock
        self.mac = mac
        self.ip = ip

    def __str__(self):
        return f"User ID: {self.conn_id} | Socket ID: {self.sock} | MAC: {self.mac} | IP: {self.ip}"


connections = []
valid_ids = [1, 2, 3]


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
        if connections[i].ram == conn:
            found = True
        else:
            i += 1
    if found:
        connections.pop(i)
    conn.close()  # Close the connection


def server_program():
    try:
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
            socket_thread.start()

    # Stop server
    except KeyboardInterrupt:
        stop = True
        for connection in connections:
            connection.ram.close()


if __name__ == '__main__':
    server_program()
