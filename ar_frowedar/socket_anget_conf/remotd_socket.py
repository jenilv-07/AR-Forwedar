import socket
from struct import pack, unpack

class WazuhInternalError():
    def __init__(self, message):
        print(message)


class MySocket:
    MAX_SIZE = 65536

    def __init__(self, path):
        self.path = path
        self._connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __enter__(self):
        return self

    def _connect(self):
        try:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(self.path)
        except FileNotFoundError as e:
            print(f"file is not exitst ERROR : {e}")
        except ConnectionRefusedError as e:
            print(f"connection refused ERROR : {e}")
        except Exception as e:
            print("ERROR : e")

    def close(self):
        self.s.close()

    def send(self, msg_bytes, header_format="<I"):
        if not isinstance(msg_bytes, bytes):
            print("Type must be bytes")
        

        try:
            sent = self.s.send(pack(header_format, len(msg_bytes)) + msg_bytes)
            if sent == 0:
                print(1014, "Number of sent bytes is 0")
            return sent
        except Exception as e:
            print(f"ERROR : {e}")

    def receive(self, header_format="<I", header_size=4):

        try:
            size = unpack(header_format, self.s.recv(header_size, socket.MSG_WAITALL))[0]
            return self.s.recv(size, socket.MSG_WAITALL)
        except Exception as e:
            print(f"ERROR : {e}")

dest_socket = "/var/ossec/queue/sockets/remote"

agent_id = input("insert the agnet id : ")
component = 'com'
configuration = 'active-response'
GETCONFIG_COMMAND = "getconfig"

# Simple socket message
msg = f"{str(agent_id).zfill(3)} {component} {GETCONFIG_COMMAND} {configuration}"

# Socket connection
try:
    s = MySocket(dest_socket)
except WazuhInternalError:
    print("wazuh WazuInternalError ------------------------------------")
except Exception as unhandled_exc:
    print(f"ERROR {unhandled_exc}")

# Send message
try:
    s.send(msg.encode)
    print("-------------- SEND THE MSG ----------------")
except Exception as e:
    print(f"ERROR : {e}")
    
# Receive response
try:
    # Receive data length
    rec_msg_ok, rec_msg = s.receive().decode().split(" ", 1)
    print("--------------- MSG RECV SUCCSESFULLY -----------------")
    print(f"rec_msg_ok : {rec_msg_ok} | rec_msg : {rec_msg}")
except ValueError as e:
    print(f"ERROR {e}")
finally:
    s.close()
            
