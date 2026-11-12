import sys
import os
from getpass import getpass
from pick import pick
import socket
import threading
from dotenv import load_dotenv
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

load_dotenv()
keyword = os.environ["SHARED_KEY"]
chat_salt = os.environ["CHAT_SALT"].encode()
shared_kdf = Argon2id(
    salt=chat_salt,
    length=32,
    iterations=3,
    lanes=4,
    memory_cost=64 * 1024,
    ad=None,
    secret=None,
)
# Derived KDF key made with the shared chat_salt for vigenere encryption/decryption.
vigenere_key = list(shared_kdf.derive(keyword.encode()))

def vigenere(data, mode):
    output = bytearray()
    for i, b in enumerate(data):
        shift = vigenere_key[i % len(vigenere_key)]
        if mode == "encrypt":
            output.append((b + shift) % 256)
        elif mode == "decrypt":
            output.append((b - shift) % 256)
    return bytes(output)


def encrypt(text):
    return vigenere(text.encode("utf-8"), "encrypt").hex().encode()


def decrypt(line):
    return vigenere(bytes.fromhex(line.decode()), "decrypt").decode()


def send_encrypted(sock, text):
    sock.sendall(encrypt(text) + b"\n")

# Wait for incoming data from server
def receive(socket, signal, username_input):
    buffer = b""
    while signal:
        try:
            data = socket.recv(4096)
            if not data:
                break
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                message = decrypt(line)

                # Pretty terminal magic.
                sys.stdout.write("\r\033[K")
                print(message)
                sys.stdout.write(f"{username_input}: ")
                sys.stdout.flush()
        except:
            print("\nYou have been disconnected from the server")
            signal = False
            break


# Get host and port
host = input("Host: ")
port = int(input("Port: "))

# Choose login or register
title = "Log in or register?"
options = ["Log In", "Register"]

option, index = pick(options, title, indicator=">")
print("\n" + option)

username_input = input("\t" + "Username: ")
password_input = getpass("\t" + "Password: ")

# Attempt connection to server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
except:
    print("Could not make a connection to the server")
    input("Press enter to quit")
    sys.exit(0)

# Send authentication data to server (option, username, password)
try:
    send_encrypted(sock, option)
    send_encrypted(sock, username_input)
    send_encrypted(sock, password_input)

    # Wait for server authentication response
    response_buffer = b""
    while b"\n" not in response_buffer:
        chunk = sock.recv(1024)
        if not chunk:
            break
        response_buffer += chunk

    response_line, _ = response_buffer.split(b"\n", 1)
    response_msg = decrypt(response_line)
    print("Server response:", response_msg)

    if "successful" not in response_msg.lower():
        print("Authentication failed. Exiting.")
        sock.close()
        input("Press enter to quit")
        sys.exit(0)

except Exception as e:
    print(f"Error during authentication: {e}")
    sock.close()
    sys.exit(0)

# Print initial prompt
sys.stdout.write(f"{username_input}: ")
sys.stdout.flush()

# Create new thread to wait for data
receiveThread = threading.Thread(
    target=receive, args=(sock, True, username_input), daemon=True
)
receiveThread.start()

# Send data to server using sys.stdin.readline for pretty terminal
while True:
    message = sys.stdin.readline()
    if not message:
        break
    message = message.strip() # Remove leaning and trailing whitespaces + \n
    if message:
        send_encrypted(sock, message)

    # Re-print the prompt on the new line after you hit enter
    sys.stdout.write(f"{username_input}: ")
    sys.stdout.flush()