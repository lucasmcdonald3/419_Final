# Secrets, encryption, decryption
import shamir
import base64
from Crypto import Random
from Crypto.Cipher import AES
# Network, sending messages
import socket
address = ("localhost", 8000)
import sys
import random
from ast import literal_eval as make_tuple
from threading import Thread
# Log analysis
import glob

messages = {} # key is enc_msg, val is [share1, share2, ... ]

# Encryption parameters
reconstruction_threshold = 3    # Number of shares needed to reconstruct message
num_third_parties = 5           # Number of third parties who receive a share
BS = 16                         # AES block size

pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

# Returns tuple (encrypted message, partial secret shares)
def encrypt_message(message_text):
    message_text = pad(message_text).encode('utf-8')
    iv = Random.new().read(AES.block_size)
    key, shares = shamir.make_random_shares(reconstruction_threshold, num_third_parties + reconstruction_threshold)
    key = (key).to_bytes(32, byteorder='big')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (base64.b64encode(iv + cipher.encrypt(message_text)), shares)

# Returns original message_text
def decrypt_message(enc_message, shares):
    message = base64.b64decode(enc_message)
    iv = message[:AES.block_size]
    key = shamir.recover_secret(shares)
    key = (key).to_bytes(32, byteorder='big')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(message[AES.block_size:])).decode('utf-8')

# Key is client's username, value is (address, listen port)
clients = {} 
# List of servers a client trusts (connects to on startup)
servers = [] 
# List of messages client has received
delivered_messages = set()

# Forwards enc_msg and share to dst_user
def forward_msg(dst_user, enc_msg, share, port):

    # If dst_user is unknown, do nothing
    if dst_user not in clients:
        return

    # Forward message
    dst_address = make_tuple(clients[dst_user])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(dst_address)
    sock.send("FORWARDED\x80{}\x80{}\x80\n".format(enc_msg, share).encode('utf-8'))

    # Log encrypted message with this share
    with open(f"msgs_{port}.log", 'a+') as f:
        f.write(dst_user + "\x80" + enc_msg + "\x80" + share + "\x80\n")

# Registers the client with this server
def register_client(client_address, username):
    clients[username] = client_address
    print("{}: {}".format(username, client_address))

# Handles packets received by server
def handle_server_msg(msg, address):
    msg_parts = msg.split('\x80')
    if msg_parts[0] == "REGISTER":
        register_client(msg_parts[1], msg_parts[2])
    elif msg_parts[0] == "FORWARD":
        forward_msg(msg_parts[1], msg_parts[2], msg_parts[3], address[1])
    
# Loop for server
def server():
    port = 8000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Servers listen on first open port above 8000
    while True:
        address = ("localhost", port)
        print(address)
        try:
            server_socket.bind(address)
            break
        except:
            port += 1
    server_socket.listen(10)
    print(f"Listening on port {address[1]}")

    # Handle all messages
    while True:
        connection, address = server_socket.accept()
        buf = connection.recv(1024)
        if len(buf) > 0:
            handle_server_msg(buf.decode('utf-8'), address)

# Client receives a message
def recv_msg(enc_msg, share):
    enc_msg = enc_msg.encode('utf-8')
    # Save the partial share
    try:
        messages[enc_msg].append(make_tuple(share))
    except:
        messages[enc_msg] = [make_tuple(share)]
    # Decode message if possible
    if len(messages[enc_msg]) >= reconstruction_threshold and enc_msg not in delivered_messages:
        print(decrypt_message(enc_msg, messages[enc_msg]))
        delivered_messages.add(enc_msg)

# Handles packets received by clients
def handle_client_msg(msg):
    msg_parts = msg.split("\x80")
    if msg_parts[0] == "FORWARDED":
        recv_msg(msg_parts[1], msg_parts[2])

# Main client loop
def client():
    username = input("Enter a username: ")
    port = 9000
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Clients listen on first open port above 9000
    while True:
        address = ("localhost", port)
        #print(address)
        try:
            client_socket.bind(address)
            break
        except:
            port += 1
    client_socket.listen(10)

    # Get all open servers
    for i in range(30):
        try:
            connect_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_socket.connect(('localhost', 8000 + i))
            connect_socket.send("REGISTER\x80{}\x80{}\x80\n".format(address, username).encode('utf-8'))
            servers.append(('localhost', 8000+i))
        except:
            pass
    print("Found {} servers".format(len(servers)))

    # Run chat interface and networking
    chat_thread = Thread(target = chat, args = [username])
    client_thread = Thread(target = client_listen, args = [client_socket])
    chat_thread.start()
    client_thread.start()
    chat_thread.join()
    client_thread.join()

# Client listens for messages
def client_listen(client_socket):
    while True:
        connection, address = client_socket.accept()
        buf = connection.recv(1024)
        if len(buf) > 0:
            handle_client_msg(buf.decode('utf-8'))

# Chat interface
def chat(username):
    print(" < Press Enter to send a private message > \n")
    while True:
        enter = input()
        if enter != "":
            continue
        dst_user = input("Send message to: ")
        msg = input("Message to {}: ".format(dst_user))
        selected_servers = random.choices(servers, k=num_third_parties)
        enc_msg, shares = encrypt_message("{}: ".format(username) + msg)
        for i in range(num_third_parties):
            server_addr = selected_servers[i]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(server_addr)
                sock.send("FORWARD\x80{}\x80{}\x80{}\x80\n".format(dst_user, enc_msg.decode('utf-8'), shares[i]).encode('utf-8'))
            except:
                # Server failed
                pass

if __name__ == "__main__":
    machine_type = sys.argv[1]
    if machine_type == "server":
        server()
    elif machine_type == "client":
        client()

# Reconstructs the encrypted message from logs in the log_directory
def decode_message_from_logs(enc_msg):
    keys = []
    log_directory = '.'
    logs = glob.glob(log_directory + '/*.log')
    for log in logs:
        with open(log) as f:
            lines = f.readlines()
            for line in lines:
                if enc_msg in line:
                    split = line.split('(')
                    key = make_tuple('(' + split[-1][:-3] + ')')
                    keys.append(key)
    return decrypt_message(enc_msg, keys)
    