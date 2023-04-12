import pika

credentials = pika.PlainCredentials('sergi', 'EETAC2023')
connection = pika.BlockingConnection(
    pika.ConnectionParameters('147.83.118.153', credentials=credentials))
channel = connection.channel()

channel.exchange_declare(exchange='test', exchange_type='direct')

result = channel.queue_declare(queue='', exclusive=True)
queue_name = result.method.queue

channel.queue_bind(
    exchange='test', queue=queue_name, routing_key='fec')

print(' [*] Waiting for logs. To exit press CTRL+C')


def callback(ch, method, properties, body):
    print(" [x] %r:%r" % (method.routing_key, body))


channel.basic_consume(
    queue=queue_name, on_message_callback=callback, auto_ack=True)

channel.start_consuming()
