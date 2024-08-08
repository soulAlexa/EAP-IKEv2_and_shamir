from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import random
import socket
import string
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


def client_program():
    host = '127.0.0.1'
    port = 5001
    pswd = input('Enter password: ')
    if SHA256.new(data=str(pswd).encode()).hexdigest() != hashPasswd:
        print('Invalid password')
        return
    print('Correct password!')
    client_socket = socket.socket()
    client_socket.connect((host, port))
    K = randomStr(8)
    print(f'1. K={K} - сгенерированный открытый ключ')
    message = enc(bytearray(K.encode("utf8")), P.encode("utf8")) #Ep(K')
    client_socket.send(message)
    print('   send Ep(K) - отправка на сервер зашифрованного на P ключа K')
    rec = client_socket.recv(1024)
    k = dec(dec(bytearray(rec), P.encode("utf8")), bytearray(K.encode("utf8")))
    print(f'3. dec k = {k.decode("utf8")} - расшифровка полученного от сервера секретного ключа k')
    Ra = randomStr(100)
    print(f'   Ra = {Ra} - сгенерированная случайная строка')
    client_socket.send(enc(Ra.encode("utf8"), k)) #Ek(Ra)
    print(f'   send Ek(Ra) - отправка на сервер зашифрованной на k строки Ra')
    rec = client_socket.recv(1024)
    recRab = dec(rec, k)
    print(f'5. Received Ra, Rb = {recRab.decode("utf8")} - расшифрованное сообщение Ek(Ra, Rb)')
    if bytes(recRab).decode("utf8")[0:100] != Ra:
        print('Generated string Ra and received string Ra dont match!')
        print('Server authentication failed')
        return
    print('   Server authentication has passed')
    Rb = recRab.decode("utf8")[100:200]
    print(f'   Decrypted Rb = {Rb} - расшифрованная строка Rb')
    client_socket.send(enc(Rb.encode(), k))
    print('   Sent Rb - отправка на сервер зашифрованной на k строки Rb')
    message = input("-> ")
    while message.lower().strip() != 'bye':
        client_socket.send(enc(message.encode("utf8"), k))
        data = client_socket.recv(1024)
        print('Received from server: ' + dec(data, k).decode("utf8"))
        message = input('-> ')
    client_socket.close()


if __name__ == '__main__':
    client_program()
