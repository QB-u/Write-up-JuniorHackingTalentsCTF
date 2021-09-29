# Repeated key xor
# Tìm hiểu thêm tại đây: https://en.wikipedia.org/wiki/XOR_cipher#Example
def encrypt(message: str, key: bytes) -> bytes:
    # chuyển string message thành byte
    byte_message = message.encode('utf-8')

    ciphertext = []
    # đi qua từng byte trong message
    for index in range(len(byte_message)):
        # nếu index vượt quá độ dài key, ta dùng lại key bắt đầu từ byte đầu tiên (từ đó có tên repeated key xor)
        current = byte_message[index] ^ key[index % len(key)]
        ciphertext.append(current)
    return bytes(ciphertext)

# Có vẻ như 1 byte là không đủ an toàn, lần này mình sẽ dùng cả 32 bytes cho key
key = open("xor_revenge_secret.txt", "rb").read()
message = open("message.txt").read().strip()
ciphertext = encrypt(message, key)

# Xuất ra độ dài key và bản mã vào file output.txt
f = open("output.txt", "w")
f.write('Key length: %d\n' % len(key))
f.write('Ciphertext: 0x' + ciphertext.hex())
f.close()
