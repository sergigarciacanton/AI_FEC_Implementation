import json
import time
import pika
import threading
import ctypes


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


def subscribe(conn, key):
    channel = conn.channel()

    channel.exchange_declare(exchange='test', exchange_type='direct')

    queue = channel.queue_declare(queue='', exclusive=True).method.queue

    channel.queue_bind(
        exchange='test', queue=queue, routing_key=key)

    print('[*] Waiting for published data. To exit press CTRL+C')

    def callback(ch, method, properties, body):
        print("[I] Received message. Key: " + str(method.routing_key) + ". Message: " + body.decode("utf-8"))

    channel.basic_consume(
        queue=queue, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()


def publish(key, message):
    conn = pika.BlockingConnection(
        pika.ConnectionParameters('147.83.118.153', credentials=pika.PlainCredentials('sergi', 'EETAC2023')))
    try:
        channel = conn.channel()

        channel.exchange_declare(exchange='test', exchange_type='direct')

        channel.basic_publish(
            exchange='test', routing_key=key, body=message)
        print("[I] New current status. Sent message. Key: " + key + ". Message: " + message)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()


def kill_thread(thread_id):
    ret = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), ctypes.py_object(SystemExit))
    if ret == 0:
        raise ValueError("Thread ID " + str(thread_id) + " does not exist!")
    elif ret > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
    print('[I] Successfully killed thread ' + str(thread_id))


subscribe_connection = pika.BlockingConnection(
    pika.ConnectionParameters('147.83.118.153', credentials=pika.PlainCredentials('sergi', 'EETAC2023')))
subscribe_thread = threading.Thread(target=subscribe, args=(subscribe_connection, 'fec'))
current_state = Fec(2048, 30, 32, 1000, 1)


def main():
    try:
        subscribe_thread.daemon = True
        subscribe_thread.start()

        while True:
            publish('fec', json.dumps(current_state.__dict__))
            time.sleep(1)
    except KeyboardInterrupt:
        kill_thread(subscribe_thread.ident)
        subscribe_thread.join()
        subscribe_connection.close()


if __name__ == '__main__':
    main()
