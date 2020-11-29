#========================CHAT APPLICATION WITH DATA ENCRYPTION AND INTEGRITY CHECK====================#
import socket 
import sys
import time
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
#==================================== Socket instance
s=socket.socket()
host=socket.gethostname()
print("Server will start on host:",host)
port=5544
s.bind((host,port))
print("Server is bound successfully")
s.listen(1)
conn,addr=s.accept()
print(addr,"has connected")
#====================================Encrypt 
def encrypt(msg):
    key = ("There are darknesses in life and there are lights, and you are one of the lights, the light of all lights.") #from Dracula by Bram Stoker 
    BLOCK_SIZE = 16
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    msg = pad(msg)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    encrypted = base64.b64encode(iv + cipher.encrypt(msg))
    return encrypted
#====================================Decrypt 
def decrypt(ciphertext):
    key = ("There are darknesses in life and there are lights, and you are one of the lights, the light of all lights.") #from Dracula by Bram Stoker 
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[16:]))
    return bytes.decode(decrypted)
#====================================Integrity CRC
def crc(data):
    key=str ('1101')
    k= len(key)
    i=0
    for i in range(k-1):
        data=data+"0"
    int_data= int(data,2)
    divd= int_data
    divs= key
    def xor(x, y): 
        res = [] 
        for i in range(1, len(y)): 
            if x[i] == y[i]: 
                res.append('0') 
            else: 
                res.append('1') 
    
        return ''.join(res)
    def modulo2(divid, divs):
        halt= len(divs)
        sub = divid[0 : halt]
        while halt < len(divid):
            if sub[0] == '1': 
                sub = xor(divs, sub) + divid[halt] 
            else:   
                sub = xor('0'*halt, sub) + divid[halt] 
            halt += 1 
        if sub[0] == '1': 
            sub = xor(divs, sub) 
        else: 
            sub = xor('0'*halt, sub)   
        checkword = sub 
        return checkword
    for i in range(1,3):    
        rem= modulo2(data, key)
        halt= len(rem)
        new_len=len(data)-halt 
        data=data[0:new_len]
        sender_data=data +rem
        #print("The Hash value = ",sender_data)
        return sender_data
#==================================== Binary to string
def btos(string):
    #print(string, "this is in df")
    binary_int = int(str(string), 2)
    #print(binary_int)
    byte_number = binary_int.bit_length() + 7 // 8
    #print(byte_number)
    binary_array = binary_int.to_bytes(byte_number, "big")
    #print(binary_array)
    ascii_text = binary_array.decode()
    #print(ascii_text)
    return ascii_text
#==================================== String to binary
def stob(z):
    byte_array = z.encode()
    binary_int = int.from_bytes(byte_array, "big")
    binary_string = bin(binary_int)
    w=binary_string[2:]
    return w
#================================ MAIN LOOP
while 1:
    #================================ RECV MSG
    
    msg=input("YOU:>>")
    encrypted_text=str(encrypt(msg))
    hash_code=crc(stob(encrypted_text))
    print("\nEncryption of message :",encrypted_text)
    print("\nHash of encrypted text :", hash_code,"\n")
    final_msg=str(encrypted_text+'~'+hash_code)
    print("\nMessage sent to reciever with hash code\n")
    conn.send(final_msg.encode())
    print("\n*****************************\n")
    #================================ SND MSG
    r_msg=conn.recv(1024).decode()
    cp=str(r_msg).split('~')
    sender_hash=str(cp[1])
    print("\n*************** Message recieved *************")
    print("\nrecieved message :",str(cp[0]))
    print("\nhash of recieved message :",sender_hash)
    decrypted_text=decrypt(str(cp[0][2:-1]))
    rec_hash=crc(stob(str(cp[0])))
    if rec_hash==sender_hash:
        print("~~~~ Integrity verified and message decrypted ~~~~~\n")
        print("FRIEND:>>",decrypted_text,"\n")
    else:
        print("\nIntegrity check of sender message failed\n")
    print("\n*****************************\n")
    
