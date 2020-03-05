#!/usr/bin/env python3

'Usage: python3 {:s} <server> <port>'

import sys
import socket
from time import sleep


def main():
    if len(sys.argv) != 3:
        print('{:s}'.format(__doc__.format(sys.argv[0])))
        sys.exit()

    server = sys.argv[1]
    port = int(sys.argv[2])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server, port))

        (server_host, server_port) = sock.getpeername()

        print('Connected to: {}:{}'.format(server_host, server_port))

        sleep(180)


if __name__ == '__main__':
    main()