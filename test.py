import json
import socket


class Fec:
    def __init__(self, gpu, ram, hd, bw, rtt):
        self.gpu = gpu
        self.ram = ram
        self.hd = hd
        self.bw = bw
        self.rtt = rtt

    def __str__(self):
        return f"GPU: {self.gpu} cores | RAM: {self.ram} GB | " \
               f"HD: {self.hd} GB | BW: {self.bw} kbps | RTT: {self.rtt} ms"


current_state = Fec(2048, 30, 32, 1000, 1)
print(json.dumps(current_state.__dict__))
message = json.dumps(dict(type="fec", data=current_state.__dict__))
print('Sent: ' + message)
rec = json.loads(message)
print('Received fake: ' + str(rec))
print(rec['type'])
print(rec['data']['ram'])

host = '147.83.118.153'
port = 5000

client_socket = socket.socket()
client_socket.connect((host, port))

while message.lower().strip() != 'bye':
    client_socket.send(message.encode())
    data = client_socket.recv(1024).decode()

    print('Received from server: ' + data)

    message = input(' -> ')
client_socket.close()
