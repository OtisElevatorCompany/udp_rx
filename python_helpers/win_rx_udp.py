import socket

UDP_IP = ""
UDP_PORT = 50300

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

print("python - sockets built\n")
counter = 0
while True:
    print("python - awaiting new connection...")
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    counter += 1
    print("python - ", counter)
    print("python - received message: {}\tfrom: {}".format(data, addr))