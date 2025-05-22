import ssl
import socket
import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_secure_server_socket(host='127.0.0.1', port=4433):
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    context.set_ciphers('ALL:@SECLEVEL=0')

    bindsock = socket.socket()
    bindsock.bind((host, port))
    bindsock.listen(5)
    logging.info(f"Listening on {host}:{port}")

    while True:
        newsocket, fromaddr = bindsock.accept()
        logging.info(f"Connection from {fromaddr}")
        try:
            sslconn = context.wrap_socket(newsocket, server_side=True)
            sslconn.sendall(b"Welcome to the SSL server.\n")
            sslconn.close()
        except Exception as e:
            logging.error(f"SSL handshake failed: {e}")

def log_daily_metrics(metrics):
    timestamp = datetime.datetime.utcnow().isoformat()
    for key, value in metrics.items():
        logging.info(f"{timestamp} - Metrics - {key}: {value}")


def parse_user_agent(user_agent):
    if 'Chrome' in user_agent:
        return 'Chrome'
    elif 'Firefox' in user_agent:
        return 'Firefox'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        return 'Safari'
    elif 'MSIE' in user_agent or 'Trident' in user_agent:
        return 'Internet Explorer'
    else:
        return 'Other'

if __name__ == "__main__":
    log_daily_metrics({"uptime_hours": 12, "connections_today": 57})
    create_secure_server_socket()