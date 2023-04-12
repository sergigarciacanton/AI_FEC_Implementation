import pika
import sys

credentials = pika.PlainCredentials('sergi', 'EETAC2023')
connection = pika.BlockingConnection(
    pika.ConnectionParameters('147.83.118.153', credentials=credentials))
channel = connection.channel()

channel.exchange_declare(exchange='logs', exchange_type='fanout')

message = ' '.join(sys.argv[1:]) or "info: Hello World!"
channel.basic_publish(exchange='logs', routing_key='', body=message)
print(" [x] Sent %r" % message)
connection.close()
