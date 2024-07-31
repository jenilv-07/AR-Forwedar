import socket
from struct import pack, unpack
from multiprocessing import Process
import time

class WazuhInternalError(Exception):
    pass

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
            print(f"File does not exist ERROR: {e}")
        except ConnectionRefusedError as e:
            print(f"Connection refused ERROR: {e}")
        except Exception as e:
            print(f"ERROR: {e}")

    def close(self):
        self.s.close()

    def send(self, msg_bytes, header_format="<I"):
        if not isinstance(msg_bytes, bytes):
            print("Type must be bytes")
            return

        try:
            sent = self.s.send(pack(header_format, len(msg_bytes)) + msg_bytes)
            if sent == 0:
                print("ERROR: Number of sent bytes is 0")
            return sent
        except Exception as e:
            print(f"ERROR: {e}")

    def receive(self, header_format="<I", header_size=4):
        try:
            size = unpack(header_format, self.s.recv(header_size, socket.MSG_WAITALL))[0]
            return self.s.recv(size, socket.MSG_WAITALL)
        except Exception as e:
            print(f"ERROR: {e}")

def handle_agent(agent_id, response_queue):
    dest_socket = "/var/ossec/queue/sockets/remote"
    component = 'com'
    configuration = 'active-response'
    GETCONFIG_COMMAND = "getconfig"

    msg = f"{str(agent_id).zfill(3)} {component} {GETCONFIG_COMMAND} {configuration}"

    print(f"Encoded MSG for agent {agent_id}: {msg.encode()}")

    try:
        with MySocket(dest_socket) as s:
            print(f"Connected to the socket: {dest_socket}")

            # Send message
            s.send(msg_bytes=msg.encode())
            print("-------------- SEND THE MSG ----------------")

            # Receive response
            rec_msg_ok, rec_msg = s.receive().decode().split(" ", 1)
            print("--------------- MSG RECV SUCCESSFULLY -----------------")
            print(f"rec_msg_ok: {rec_msg_ok} | rec_msg: {rec_msg}")

            response_queue.put((agent_id, rec_msg_ok, rec_msg))
    except WazuhInternalError:
        print("WazuhInternalError ------------------------------------")
        response_queue.put((agent_id, "error", "WazuhInternalError"))
    except Exception as unhandled_exc:
        print(f"ERROR: {unhandled_exc}")
        response_queue.put((agent_id, "error", str(unhandled_exc)))

def process_agents(agent_list, timeout=20):
    from multiprocessing import Queue

    processes = []
    response_queue = Queue()

    for agent_id in agent_list:
        p = Process(target=handle_agent, args=(agent_id, response_queue))
        processes.append(p)
        p.start()

    for p in processes:
        p.join(timeout=timeout)
        if p.is_alive():
            p.terminate()
            response_queue.put((p.name, "ok", "Response timeout"))

    responses = []
    while not response_queue.empty():
        responses.append(response_queue.get())

    return responses

if __name__ == "__main__":
    agent_list = []
    for i in range(1,1001):
        agent_list.append(i)
    
    
    responses = process_agents(agent_list)

    for agent_id, rec_msg_ok, rec_msg in responses:
        print(f"Agent {agent_id} - rec_msg_ok: {rec_msg_ok} | rec_msg: {rec_msg}")
