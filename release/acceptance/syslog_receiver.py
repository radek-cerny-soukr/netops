import json
import socket
import ssl
import sys
import threading

cert, key, out = sys.argv[1], sys.argv[2], sys.argv[3]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(cert, key)
lock = threading.Lock()


def read_exact(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def serve(raw):
    try:
        connection = context.wrap_socket(raw, server_side=True)
    except ssl.SSLError as error:
        with lock, open(out, "a") as stream:
            stream.write(json.dumps({"event": "tls_failed", "error": str(error)[:120]}) + "\n")
        raw.close()
        return
    with lock, open(out, "a") as stream:
        stream.write(json.dumps({"event": "tls_accepted"}) + "\n")
    reason = "EOFError"
    try:
        while True:
            length = b""
            while True:
                byte = read_exact(connection, 1)
                if byte == b" ":
                    break
                if not byte.isdigit() or len(length) > 9:
                    raise ValueError("not octet-counted framing")
                length += byte
            message = read_exact(connection, int(length))
            with lock, open(out, "a") as stream:
                stream.write(json.dumps({"event": "message", "length": int(length), "text": message.decode("utf-8", "replace")}) + "\n")
    except (EOFError, ValueError, OSError) as error:
        reason = type(error).__name__
    finally:
        try:
            connection.unwrap()
        except (OSError, ValueError):
            pass
        connection.close()
        with lock, open(out, "a") as stream:
            stream.write(json.dumps({"event": "closed", "reason": reason}) + "\n")


listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", 6514))
listener.listen(16)
while True:
    raw, _ = listener.accept()
    threading.Thread(target=serve, args=(raw,), daemon=True).start()
