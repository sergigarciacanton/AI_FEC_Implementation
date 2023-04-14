import socket
import json
import pika
import threading
import ctypes


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


fec_list = []

control_socket = socket.socket()
rabbit_conn = pika.BlockingConnection(
    pika.ConnectionParameters('147.83.118.153', credentials=pika.PlainCredentials('sergi', 'EETAC2023')))
subscribe_thread = threading.Thread(target=subscribe, args=(rabbit_conn, 'fec'))
current_state = Fec(2048, 30, 1000, 1)
previous_state = None


def main():
    try:
        global previous_state
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
            if previous_state != current_state:
                print('[I] New current state! Sending to control...')
                control_socket.send(json.dumps(dict(type="fec", data=current_state.__dict__)).encode())
                response = json.loads(control_socket.recv(1024).decode())
                if response['res'] != 200:
                    print('[!] Error ' + response['res'])
                previous_state = current_state
    except KeyboardInterrupt:
        print('[!] Stopping...')
        kill_thread(subscribe_thread.ident)
        subscribe_thread.join()
        rabbit_conn.close()
        control_socket.close()
    except SystemExit:
        print('[!] Stopping...')
        kill_thread(subscribe_thread.ident)
        subscribe_thread.join()
        rabbit_conn.close()
        control_socket.close()


if __name__ == '__main__':
    main()
