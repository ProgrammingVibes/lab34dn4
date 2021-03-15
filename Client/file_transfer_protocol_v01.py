#!/usr/bin/env python3

########################################################################
#
# GET File Transfer
#
# When the client connects to the server, it immediately sends a
# 1-byte GET command followed by the requested filename. The server
# checks for the GET and then transmits the file. The file transfer
# from the server is prepended by an 8 byte file size field. These
# formats are shown below.
#
# The server needs to have REMOTE_FILE_NAME defined as a text file
# that the client can request. The client will store the downloaded
# file using the filename LOCAL_FILE_NAME. This is so that you can run
# a server and client from the same directory without overwriting
# files.
#
########################################################################

import socket
import argparse

########################################################################

# Define all of the packet protocol field lengths. See the
# corresponding packet formats below.
CMD_FIELD_LEN = 1  # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN = 8  # 8 byte file size field.

# Packet format when a GET command is sent from a client, asking for a
# file download:

# -------------------------------------------
# | 1 byte GET command  | ... file name ... |
# -------------------------------------------

# When a GET command is received by the server, it reads the file name
# then replies with the following response:

# -----------------------------------
# | 8 byte file size | ... file ... |
# -----------------------------------

# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer. For now, we only define the "GET" command,
# which tells the server to send a file.

CMD = { 
    "get" : 1,
    "put" : 2, 
    "rlist": 3
}

MSG_ENCODING = "utf-8"


########################################################################
# SERVER
########################################################################

class Server:
    HOSTNAME = "0.0.0.0"

    PORT = 50000
    RECV_SIZE = 1024
    BACKLOG = 5

    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

    # This is the file that the client will request using a GET.
    REMOTE_FILE_NAME = "remotefile.txt"

    # REMOTE_FILE_NAME = "bee.jpg"

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create the TCP server listen socket in the usual way.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        try:
            while True:
                self.connection_handler(self.socket.accept())
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()

    def connection_handler(self, client):
        connection, address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))

        # Read the command and see if it is a GET.
        cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder='big')
        if cmd != CMD["GET"]:
            print("GET command not received!")
            return

        # The command is good. Now read and decode the requested
        # filename.
        filename_bytes = connection.recv(Server.RECV_SIZE)
        filename = filename_bytes.decode(MSG_ENCODING)

        # Open the requested file and get set to send it to the
        # client.
        try:
            file = open(filename, 'r').read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes

        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            # print("Sent packet bytes: \n", pkt)
            print("Sending file: ", Server.REMOTE_FILE_NAME)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return


########################################################################
# CLIENT
########################################################################

class Client:
    RECV_SIZE = 1024
    MSG_ENCODING = "utf-8"

    BROADCAST_ADDRESS = "255.255.255.255"
    SERVICE_PORT = 30000
    ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_PORT)

    SCAN_CYCLES = 3
    SCAN_TIMEOUT = 5

    SCAN_CMD = "scan"
    CONNECT_CMD = "connect"
    BYE_CMD = "bye"
    LLIST_CMD = "llist"
    LOCAL_CMD = [SCAN_CMD, CONNECT_CMD, BYE_CMD, LLIST_CMD]
    SERVICE_DISCOVERY_MSG = "SERVICE DISCOVERY"
    SD_MSG_ENCODED = SERVICE_DISCOVERY_MSG.encode(MSG_ENCODING)

    INPUT_PARSER = argparse.ArgumentParser()
    INPUT_PARSER.add_argument("cmd")
    INPUT_PARSER.add_argument("--opt1", required=False)
    INPUT_PARSER.add_argument("--opt2", required=False)

    # Define the local file name where the downloaded file will be
    # saved.
    LOCAL_FILE_NAME = "localfile.txt"

    # LOCAL_FILE_NAME = "bee1.jpg"

    def __init__(self):
        self.broadcast_socket = None
        self.transfer_socket = None
        self.connected = False
        self.setup_broadcast_socket()
        self.setup_transfer_socket()
        self.handle_client_requests()

    def setup_broadcast_socket(self):
        try:
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            self.broadcast_socket.settimeout(Client.SCAN_TIMEOUT)
        except Exception as msg:
            print(msg)
            exit()

    def scan_for_service(self):
        scan_results = []

        for i in range(Client.SCAN_CYCLES):

            print(f"Sending broadcast scan {i}")
            self.broadcast_socket.sendto(Client.SD_MSG_ENCODED, Client.ADDRESS_PORT)

            while True:
                try:
                    recvd_bytes, address = self.broadcast_socket.recvfrom(Client.RECV_SIZE)
                    recvd_msg = recvd_bytes.decode(Client.MSG_ENCODING)

                    if (recvd_msg, address) not in scan_results:
                        scan_results.append((recvd_msg, address))
                        continue

                except socket.timeout:
                    break

        if scan_results:
            for result in scan_results:
                print(result)
        else:
            print("No services found.")

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            input_args = input("Enter a command: ").split(' ')
            if len(input_args) == 3:
                input_args.insert(2, "--opt2")
                input_args.insert(1, "--opt1")
            if len(input_args) == 2:
                input_args.insert(1, "--opt1")

            self.input_cmd = Client.INPUT_PARSER.parse_args(input_args)
            if self.input_cmd.cmd != "" and \
                    (self.input_cmd.cmd in CMD or self.input_cmd.cmd in self.LOCAL_CMD):
                break

    def setup_transfer_socket(self):
        try:
            self.transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            exit()

    def handle_client_requests(self):
        try:
            while True:
                self.get_console_input()

                if self.input_cmd.cmd in CMD:
                    if not self.connected:
                        print("Not connected to any file sharing service.")
                    else:
                        # self.get_file()
                        # self.connection_send()
                        # self.connection_receive()
                        pass

                elif self.input_cmd.cmd == Client.SCAN_CMD:
                    self.scan_for_service()

                elif self.input_cmd.cmd == Client.CONNECT_CMD:
                    self.connect_to_server()

                elif self.input_cmd.cmd == Client.BYE_CMD:
                    break

        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            print()
            print("Closing server connection ...")
            self.broadcast_socket.close()
            self.transfer_socket.close()
            exit()

    def connect_to_server(self):
        try:
            self.transfer_socket.connect((self.input_cmd.opt1, int(self.input_cmd.opt2)))
        except Exception as msg:
            print(msg)

    def socket_recv_size(self, length):
        bytes = self.transfer_socket.recv(length)
        if len(bytes) < length:
            self.transfer_socket.close()
            exit()
        return (bytes)

    def get_file(self):

        # Create the packet GET field.
        get_field = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field = Server.REMOTE_FILE_NAME.encode(MSG_ENCODING)

        # Create the packet.
        pkt = get_field + filename_field

        # Send the request packet to the server.
        self.transfer_socket.sendall(pkt)

        # Read the file size field.
        file_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN)
        if len(file_size_bytes) == 0:
            self.transfer_socket.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')

        # Receive the file itself.
        recvd_bytes_total = bytearray()
        try:
            # Keep doing recv until the entire file is downloaded.
            while len(recvd_bytes_total) < file_size:
                recvd_bytes_total += self.transfer_socket.recv(Client.RECV_SIZE)

            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), Client.LOCAL_FILE_NAME))

            with open(Client.LOCAL_FILE_NAME, 'w') as f:
                f.write(recvd_bytes_total.decode(MSG_ENCODING))
        except KeyboardInterrupt:
            print()
            exit(1)
        # If the socket has been closed by the server, break out
        # and close it on this end.
        except socket.error:
            self.transfer_socket.close()


########################################################################

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################


