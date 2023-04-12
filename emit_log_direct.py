import pika
import sys

credentials = pika.PlainCredentials('sergi', 'EETAC2023')
connection = pika.BlockingConnection(
    pika.ConnectionParameters('147.83.118.153', credentials=credentials))
channel = connection.channel()

channel.exchange_declare(exchange='direct_logs', exchange_type='direct')

severity = sys.argv[1] if len(sys.argv) > 1 else 'info'
message = ' '.join(sys.argv[2:]) or 'Hello World!'
channel.basic_publish(
    exchange='direct_logs', routing_key=severity, body=message)
print(" [x] Sent %r:%r" % (severity, message))
connection.close()
