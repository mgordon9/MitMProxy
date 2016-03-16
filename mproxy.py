import getopt
import socket
import re
from concurrent.futures import ThreadPoolExecutor
from trace import usage
from urllib.parse import urlparse
import logging
import ssl
import sys



class MitMProxy:
    def __init__(self):
        self.PORT = 50000
        self.SOCKET_READ_SIZE = 4096
        self.MAX_WORKER_SIZE = 10
        self.CERTIFICATE = 'servercert.pem'
        self.PRIVATE_KEY = 'serverkey.pem'
        self.IP = ''
        self.COUNT = 0
        self.LOG = 'HTTP_Proxy.log'

    def main(self):
        logging.basicConfig(filename=self.LOG, format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M', filemode='w', level=logging.DEBUG)
        # console = logging.StreamHandler()
        # console.setLevel(logging.DEBUG)
        # formatter = logging.Formatter('%(levelname)-8s %(message)s')
        # console.setFormatter(formatter)
        # logging.getLogger('').addHandler(console)

        self.input_parser()

        server_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_listener.bind(('', self.PORT))
        # become a server socket
        server_listener.listen(5)
        logging.debug(server_listener.getsockname()[1])

        with ThreadPoolExecutor(max_workers=self.MAX_WORKER_SIZE) as executioner:
            while 1:
                client_to_me_socket, address = server_listener.accept()
                self.IP = client_to_me_socket.getpeername()[0]
                client_request = self.non_blocking_receive(client_to_me_socket)
                connect_pattern = b'CONNECT'
                is_connect_request = re.search(connect_pattern, client_request)
                if is_connect_request is None:
                    executioner.submit(self.http_threaded_request, client_to_me_socket, client_request)
                else:
                    executioner.submit(self.set_up_ssl_connection, client_to_me_socket, client_request)



    def input_parser(self):
        try:
            opts, args = getopt.getopt(sys.argv[1:], "hvp:n:t:l:", ["help", "version", "port=", "numworker=", "timeout=", "log="])
        except getopt.GetoptError as err:
            print(err)
            self.print_help()
            sys.exit(2)
        for o, a in opts:
            if o in ("-v", "--version"):
                print('Man in the Middle Proxy Server')
                print('Version 0.1')
                print('Matthew Gordon')
                exit(0)
            elif o in ("-h", "--help"):
                self.print_help()
                sys.exit(0)
            elif o in ("-p", "--port"):
                self.PORT = int(a)
            elif o in ("-n", "--numworker"):
                self.MAX_WORKER_SIZE = a
            elif o in ("-l", "--log"):
                self.LOG = a
            else:
                assert False, "unhandled option"
                exit(2)


    def print_help(self):
        print('-h or --help\n'
              'Prints a synopsis of the application usage\n'
              '-v or --version\n'
              'Prints the name of the application, the version number\n'
              '[-p port] or [--port port]\n'
              'The port the server will be listening on\n'
              '[-n num_of_workers] or [--numworker num_of_worker]\n'
              'The maximum number of worker threads for HTTP and HTTPS requests\n'
              '[-t timeout] or [--timeout timeout]\n'
              'The time in seconds to wait for the server to respond(default is infinite)\n'
              '[-l log] or [--log log]\n'
              'Logs all HTTP and HTTPS requests and responses into the passed file.')


    def non_blocking_receive(self, read_socket):
            read_socket.setblocking(0)
            read_socket.settimeout(2)
            data = b''
            while 1:
                try:
                    new_data = read_socket.recv(self.SOCKET_READ_SIZE)
                    data = data + new_data
                    if new_data == b'' or data[-4:] == b'\r\n\r\n':
                        break
                except socket.error as e:
                    logging.warning('non blocking read: ' + str(e))
                    break
            return data


    def set_up_ssl_connection(self, client_to_me_socket, client_request):
        logging.info(client_request)
        host_pattern = b'CONNECT (.*) HTTP'
        host = re.search(host_pattern, client_request)
        client_connstream = None
        server_connstream = None
        if host is not None:
            url = host.group(1)
            url_parse = urlparse(b'http://' + url)
            port = 443
            if url_parse.port is not None:
                port = url_parse.port

            server_context = ssl.create_default_context()
            sock = socket.socket(socket.AF_INET)
            try:
                server_connstream = server_context.wrap_socket(sock, server_hostname=url_parse.hostname.decode())
            except socket.timeout as e:
                logging.error(b'server connection failed: ' + e)
                return
            server_connstream.connect((url_parse.hostname, port))

            # cert = server_connstream.getpeercert()
            # logging.debug(cert)
            # common_name, dns_list = parse_cert(cert)
            # certificate, private_key = create_cert_and_key(common_name, dns_list)

            client_to_me_socket.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            client_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            client_context.load_cert_chain(certfile=self.CERTIFICATE, keyfile=self.PRIVATE_KEY)
            try:
                client_connstream = client_context.wrap_socket(client_to_me_socket, server_side=True)
            except socket.timeout as e:
                logging.error(b'client connection failed: ' + e)
                return

        if client_connstream is None or server_connstream is None:
            logging.warning('Client stream: ' + client_connstream + '\nServer stream: ' + server_connstream)
            return
        else:
            self.https_threaded_request(client_connstream, server_connstream, url_parse.hostname)


    def http_threaded_request(self, client_to_me_socket, request):
        self.COUNT += 1
        client_data = request
        logging.info(b'HTTP FROM CLIENT: ' + client_data)

        get_pattern = b'GET (.*) HTTP'
        matched_host = re.search(get_pattern, client_data)
        if matched_host is None:
            post_pattern = b'POST (.*) HTTP'
            matched_host = re.search(post_pattern, client_data)
            if matched_host is None:
                logging.debug(b'Neither POST or GET: ' + client_data)
                client_to_me_socket.close()
                return

        url = matched_host.group(1)
        urlParse = urlparse(url)

        with open(str(self.COUNT) + '_' + self.IP + '_' + urlParse.hostname.decode('utf-8') + '.txt', 'wb') as log:
            log.write(client_data)
            me_to_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            me_to_server_socket.connect((urlParse.hostname, 80))

            me_to_server_socket.sendall(client_data)
            server_data = self.non_blocking_receive(me_to_server_socket)
            try:
                log.write(server_data)
            except Exception as e:
                print(e)
            logging.info(b'HTTP FROM SERVER: ' + server_data)
            client_to_me_socket.sendall(server_data)

        client_to_me_socket.close()
        me_to_server_socket.close()


    def https_threaded_request(self, client_to_me_socket, me_to_server_socket, host):
        self.COUNT += 1
        new_host = host.decode('utf-8')
        with open(str(self.COUNT) + '_' + self.IP + '_' + new_host + '.txt', 'wb') as log:
            client_data = self.non_blocking_receive(client_to_me_socket)
            log.write(client_data)
            logging.info(b'HTTPS(SSL) FROM CLIENT: ' + client_data)

            post_pattern = b'GET'
            matched_host = re.search(post_pattern, client_data)
            if matched_host is None:
                post_pattern = b'POST'
                matched_host = re.search(post_pattern, client_data)
                if matched_host is None:
                    logging.debug(b'Neither POST or GET: ' + client_data)
                    client_to_me_socket.close()
                    return

            me_to_server_socket = me_to_server_socket
            me_to_server_socket.sendall(client_data)
            server_data = self.non_blocking_receive(me_to_server_socket)
            client_to_me_socket.sendall(server_data)

            logging.info( b'HTTPS(SSL) FROM SERVER: ' + server_data)
            log.write(server_data)

        client_to_me_socket.close()
        me_to_server_socket.close()


    def parse_cert(cert):
        dns_pattern = 'DNS\', \'(.+?)\'+?'
        common_name_pattern = 'commonName\', \'(.*)\''

        common_name = re.search(common_name_pattern, str(cert['subject']))
        print('common_name: ' + common_name.group(1))
        dns_list = re.findall(dns_pattern, str(cert['subjectAltName']))
        print('alt_names:\n')
        count = 128;
        for x in dns_list:
            print('DNS.' + str(count) + '\t\t= ' + str(x))
            count += 1

        return common_name, dns_list


if __name__ == "__main__":
    proxy = MitMProxy()
    proxy.main()