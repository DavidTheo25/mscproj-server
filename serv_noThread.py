from servRequests import Requests

import socket

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 9001              # Arbitrary non-privileged port
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    req = Requests()
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        data = ""
        res = ""
        while True:
            data_temp = conn.recv(1024)
            data += data_temp.decode('utf-8')
            if not data_temp:
                request = data
                res = req.handle(request[:-3])
                print("res = ", res)
                print(data)
                break
            if len(data_temp) >= 3:
                if data_temp[-3:] == b"EOR":
                    request = data
                    res = req.handle(request[:-3])
                    print("res = ", res)
                    print(data)
                    break
        conn.sendall(res.encode('utf-8'))
