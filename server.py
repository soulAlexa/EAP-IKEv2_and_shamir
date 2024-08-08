import random
import socket
import string
import time

from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
block_size = 64

hashPasswd = SHA256.new(data=b'12345678').hexdigest()
P = '12345678'

def enc(data, key):
    data = pad(data, 64)
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def dec(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    return unpad(decrypted_data, 64)


def randomStr(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

def dop(data, l):
    t = bytearray(l)
    for i in range(len(data)):
        t[l-len(data)+i] = data[i]
    for i in range(l-len(data)):
        t[i] = 255
    return t
def server_program():
    # host = socket.gethostname('')
    host = '0.0.0.0'
    port = 5001
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    conn, address = server_socket.accept()
    pswd = input('Enter password: ')
    if SHA256.new(data=str(pswd).encode()).hexdigest() != hashPasswd:
        print('Invalid password')
        return
    print('Correct password!')
    print("Connection from: " + str(address))

    K = dec(bytearray(conn.recv(1024)), P.encode("utf8"))
    print(f'2. K = {K} - расшифрованный ключ K')
    k = randomStr(8)
    print(f'   k = {k} - сгенерированный случайный ключ k')
    EKk = enc(bytearray(k.encode("utf8")), K)
    message = enc(EKk, P.encode("utf8")) #Ep(EK'(k))
    conn.send(message)
    print('   send Ep(EK(k)) - отправка на клиент зашифрованного на ключе K и на ключе P ключа k')
    get = conn.recv(1024)
    Ra = dec(bytearray(get), k.encode("utf8"))
    print(f'4. dec Ra = {Ra.decode("utf8")} - расшифрованная строка Ra')
    Rb = randomStr(100)
    print(f'   Rb = {Rb} - сгенерированная случайная строка Rb')
    conn.send(enc(str(Ra.decode()+Rb).encode(), k.encode("utf8"))) #Ek(Ra)
    print('   send Ek(Ra, Rb) - отправка на клиент зашифрованной на ключе k строки Ra и Rb')
    rec = conn.recv(1024)
    recRb = dec(bytearray(rec), k.encode("utf8"))
    print(f'6. dec Rb = {recRb.decode("utf8")} - расшифрованная строка Rb')
    if recRb.decode("utf8") != Rb:
        print('Client authentication failed')
        return
    print('   Client authentication has passed')
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print("from user: " + str(dec(data, k.encode("utf8")).decode("utf8")))
        data = enc(input('-> ').encode("utf8"), k.encode("utf8"))
        conn.send(data)
    conn.close()


if __name__ == '__main__':
    server_program()
