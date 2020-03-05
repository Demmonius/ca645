#!/usr/bin/env python3

'Usage: python3 {:s} <port>'

import sys
import socket
import threading


class ThreadWorker(threading.Thread):

    def __init__(self, ns):
        self.ns = ns
        super(ThreadWorker, self).__init__()

    def run(self):
        client_host, client_port = self.ns.getpeername()
        print('Connection from: {}:{}'.format(
            client_host, client_port))
        _ = self.ns.recv(1)
        self.ns.close()


def main():
    if len(sys.argv) != 2:
        print('{:s}'.format(__doc__.format(sys.argv[0])))
        sys.exit()

    port = int(sys.argv[1])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        sock.bind(('', port))

        sock.listen(5)

        while True:
            newsock, _ = sock.accept()
            thread = ThreadWorker(newsock)
            thread.start()


if __name__ == '__main__':
    main()