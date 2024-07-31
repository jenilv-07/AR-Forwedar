import socket


class WazuhInternalError():
    def __init__(self,msg) -> None:
        print(f"ERROR : {msg}")

# path os socket
class AR_send:
    # Sizes
    OS_MAXSTR = 6144  # OS_SIZE_6144
    MAX_MSG_SIZE = OS_MAXSTR + 256

    def __init__(self, path):
        self.path = path
        self._connect()

    def _connect(self):
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.socket.connect(self.path)
            length_send_buffer = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            if length_send_buffer < self.MAX_MSG_SIZE:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.MAX_MSG_SIZE)
        except Exception as e: 
            print(f"ERROR : {e}")

    def __enter__(self):
        return self

    def send(self, msg: bytes) -> None:
        """Send a message through a socket.

        Parameters
        ----------
        msg : bytes
            The message to send.

        Raises
        ------
        WazuhInternalError(1011)
            If there was an error communicating with queue.
        """
        try:
            sent = self.socket.send(msg)

            if sent == 0:
                raise WazuhInternalError(1011, self.path)
        except socket.error:
            raise WazuhInternalError(1011, self.path)