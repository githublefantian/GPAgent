# -*- coding: utf-8 -*-
import socket
import threading
import json
import cmdhandler

LISTEN_PORT = 8080
HOST_IP = '10.10.88.173'
BUFSIZE = 1024

def linkhandler(sock, addr):
    print('Accept new connection from %s:%s' % addr)
    #sock.send('Welcome!')
    while True:
        data = sock.recv(BUFSIZE)
        if data == 'exit' or not data:
            break
        result = cmdhandler.mainbody(data)
        if result == {}:
            print('result is {}')
            sock.send(json.dumps({"code": "error"}))
        else:
            sock.send(json.dumps(result))
    sock.close()
    print ('Connection from %s %s closed.' % addr)

if __name__ == '__main__':
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST_IP, LISTEN_PORT))
        s.listen(5)
    except:
        pass
    while True:
        print('waiting for connection...')
        sock, addr = s.accept()
        print('...connected from:{}'.format(addr))
        t = threading.Thread(target=linkhandler, args=(sock, addr))
        t.start()

'''
if __name__ == '__main__':
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST_IP, LISTEN_PORT))
        s.listen(1)
    except:
        pass
    while True:
        print('waiting for connection...')
        sock, addr = s.accept()
        print('...connected from:{}'.format(addr))
        while True:
            data = sock.recv(BUFSIZE)
            if data == 'exit' or not data:
                break
            result = cmdhandler.mainbody(data)
            if result == {}:
                print('result is {}')
                sock.send(json.dumps({"code": "error"}))
            else:
                sock.send(json.dumps(result))
        sock.close()
        print ('Connection from %s %s closed.' % addr)
'''
