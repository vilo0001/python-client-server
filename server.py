import socket
import threading
import sqlite3
import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from dotenv import load_dotenv

# Get shared key from .env
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
keyword_numbers = list(shared_kdf.derive(keyword.encode("utf-8")))  # 32 numbers (0-255)

def vigenere(data, mode):
    output = bytearray()
    for i, b in enumerate(data):
        shift = keyword_numbers[i % len(keyword_numbers)]
        if mode == "encrypt":
            output.append((b + shift) % 256)
        elif mode == "decrypt":
            output.append((b - shift) % 256)
    return bytes(output)

def encrypt(text):
    return vigenere(text.encode(), "encrypt").hex().encode()

def decrypt(line):
    return vigenere(bytes.fromhex(line.decode()), "decrypt").decode()

def send_encrypted(sock, text):
    sock.sendall(encrypt(text) + b"\n")

# Variables for holding information about connections
connections = []
total_connections = 0

# Create database
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, salt BLOB, password BLOB)')
conn.commit()

# Client class, new instance created for each connected client
class Client(threading.Thread):
    def __init__(self, socket, address, id, name, signal):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.id = id
        self.name = name
        self.signal = signal
    
    def __str__(self):
        return str(self.id) + " " + str(self.address)
    
    def run(self):
        buffer = b""
        while self.signal:
            try:
                data = self.socket.recv(4096)
                if not data:
                    raise ConnectionError
            except:
                print("Client " + str(self.name) + " (" + str(self.address) + ") has disconnected")
                self.signal = False
                if self in connections:
                    connections.remove(self)
                break
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    message = decrypt(line)
                except ValueError:
                    continue
                print("ID " + str(self.id) + " (" + str(self.name) + "): " + message)
                for client in connections:
                    if client.id != self.id:
                        try:
                            send_encrypted(client.socket, f"{self.name}: {message}")
                        except:
                            pass

def registerUser(username, password):
    username = username.lower().strip()

    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )
    key = kdf.derive(password.encode())

    try:
        cursor.execute(
            "INSERT INTO users (username, salt, password) VALUES (?, ?, ?)",
            (username, salt, key),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    return True, "Registration successful."

def loginUser(username, password):
    username = username.lower().strip()
    cursor.execute("SELECT salt, password FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user is None:
        return False, "Invalid username or password."

    salt, stored_key = user
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )
    try:
        kdf.verify(password.encode(), stored_key)
        return True, "Login successful."
    except:
        return False, "Invalid username or password."

def handle_client_connection(sock, address):
    global total_connections
    try:
        data_buffer = b""
        lines = []
        while len(lines) < 3:
            chunk = sock.recv(1024)
            if not chunk:
                sock.close()
                return
            data_buffer += chunk
            while b"\n" in data_buffer and len(lines) < 3:
                line, data_buffer = data_buffer.split(b"\n", 1)
                lines.append(decrypt(line).strip())

        option, username, password = lines[0], lines[1], lines[2]

        if option == "Register":
            success, msg = registerUser(username, password)
        elif option == "Log In":
            success, msg = loginUser(username, password)
        else:
            success, msg = False, "Invalid option."

        send_encrypted(sock, msg)

        if not success:
            sock.close()
            return

        client_id = total_connections
        total_connections += 1
        new_client = Client(sock, address, client_id, username, True)
        connections.append(new_client)
        new_client.start()
        print(f"New connection: {username} at ID {client_id} ({address})")

    except Exception as e:
        print(f"Error handling connection from {address}: {e}")
        sock.close()

def newConnections(socket):
    while True:
        sock, address = socket.accept()
        threading.Thread(target=handle_client_connection, args=(sock, address), daemon=True).start()

def main():
    host = input("Host: ")
    port = int(input("Port: "))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)

    newConnectionsThread = threading.Thread(target=newConnections, args=(sock,), daemon=True)
    newConnectionsThread.start()
    print(f"Server started on {host}:{port}")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Server shutting down.")

if __name__ == "__main__":
    main()