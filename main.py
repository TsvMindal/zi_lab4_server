import subprocess
import socket
import re

CLIENT_PORT = 3000
SERVER_PORT = 4000
PRIVATE_PATH = "C:/Users/trudo/PycharmProjects/zi_lab4_client/privatekey.pem"
PUBLIC_PATH = "C:/Users/trudo/PycharmProjects/zi_lab4_client/publickey.pem"

def parse_rsa_key_info(publicOutput, privateOutput):
    modulus, publicExponent, privateExponent = 0, 0, 0
    for i in range(0, 2):
        match = re.search("modulus:\s+([\s\S]+?)publicExponent:", publicOutput)
        if match:
            value = match.group(1).replace(":", "").replace(" ", "").replace("\r\n", "")
            modulus = int(value, 16)
        match = re.search("publicExponent:\s+([\s\S]+?)privateExponent:", publicOutput)
        if match:
            value = match.group(1).replace(":", "").replace(" ", "").replace("\r\n", "").replace("(0x10001)", "")
            publicExponent = int(value)
        match = re.search("privateExponent:\s+([\s\S]+?)prime1:", publicOutput)
        if match:
            value = match.group(1).replace(":", "").replace(" ", "").replace("\r\n", "")
            privateExponent = int(value, 16)
        publicOutput = privateOutput
    return modulus, publicExponent, privateExponent

def modular_power(baseValue, exponent, modulus):
    result = 1
    while exponent:
        if exponent % 2 == 1:
            result = (result * baseValue) % modulus
        baseValue = (baseValue * baseValue) % modulus
        exponent //= 2
    return result

def process(message: int):
    privateKeyOutput = subprocess.check_output("openssl rsa -in {} -noout -text".format(PRIVATE_PATH), shell=True)
    publicKeyOutput = subprocess.check_output("openssl rsa -pubin -in {} -noout -text".format(PUBLIC_PATH), shell=True)
    modulus, publicExponent, privateExponent = parse_rsa_key_info(str(publicKeyOutput.decode("UTF-8")), str(privateKeyOutput.decode("UTF-8")))

    blindedSignature = modular_power(message, privateExponent, modulus)

    return blindedSignature

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(('localhost', SERVER_PORT))
s.listen(1)

print("Сервер запущен и ожидает подключений...")

while True:
    conn, addr = s.accept()
    print("Подключение от", addr)

    data = conn.recv(1024)
    if data:
        print("Получены данные от клиента.")
        sign = process(int(data.decode('utf-8')))
        print("Вычислена подпись.")

        response = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        response.connect(('localhost', CLIENT_PORT))
        response.sendall(str(sign).encode('utf-8'))
        response.close()
        print("Отправлена подпись клиенту")

s.close()
