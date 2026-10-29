"""Entry point for the existing portal service, using the bounded simulator."""
from decoy import Handler, Server

if __name__ == '__main__':
    server=Server(('127.0.0.1',8080),Handler)
    server.persona='portal'
    server.serve_forever()
