import sys
import os
from getpass import getpass
from pick import pick
import socket
import threading
from dotenv import load_dotenv

# Get shared key from .env
load_dotenv()
keyword = os.environ["SHARED_KEY"]
keyword_numbers = [ord(c) for c in keyword]

start = 32          # don't include new line and so on.
size = 256 - 32     # size without the first 32.

def vigenere(text, mode):
    output = ""
    for i, c in enumerate(text):
        pos = ord(c) - start
        if 0 <= pos < size:
            if mode == "encrypt":
                shift = keyword_numbers[i % len(keyword)]
                output += chr((pos + shift) % size + start)
            elif mode == "decrypt":
                shift = keyword_numbers[i % len(keyword)]
                output += chr((pos - shift) % size + start)
            else:
                output += c
        else:
            output += c
    return output

# Wait for incoming data from server
def receive(socket, signal, username_input):
    while signal:
        try:
            data = socket.recv(1024)
            if not data:
                break
            message = vigenere(data.decode("utf-8"), "decrypt")

            # 1. Clear the current line (\r moves to start, \033[K clears the line)
            sys.stdout.write("\r\033[K")
            # 2. Print the incoming message from another user
            print(message)
            # 3. Re-print the input prompt at the bottom
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
    sock.sendall((option + "\n").encode("utf-8"))
    sock.sendall((username_input + "\n").encode("utf-8"))
    sock.sendall((password_input + "\n").encode("utf-8"))

    # Wait for server authentication response
    response_buffer = b""
    while b"\n" not in response_buffer:
        chunk = sock.recv(1024)
        if not chunk:
            break
        response_buffer += chunk

    response_line, _ = response_buffer.split(b"\n", 1)
    response_msg = response_line.decode("utf-8")
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

# Create new thread to wait for data (passing username_input)
receiveThread = threading.Thread(
    target=receive, args=(sock, True, username_input), daemon=True
)
receiveThread.start()

# Send data to server using sys.stdin.readline for clean terminal flow
while True:
    message = sys.stdin.readline()
    if not message:
        break
    message = message.strip()
    if message:
        sock.sendall(vigenere(message, "encrypt").encode("utf-8"))

    # Re-print the prompt on the new line after you hit enter
    sys.stdout.write(f"{username_input}: ")
    sys.stdout.flush()
