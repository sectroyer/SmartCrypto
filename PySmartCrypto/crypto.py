from __future__ import print_function
from Crypto.Cipher import AES
import hashlib
import keys
import rijndael
import struct

BLOCK_SIZE = 16
SHA_DIGEST_LENGTH = 20
def EncryptParameterDataWithAES(input):
    iv = b"\x00" * BLOCK_SIZE
    output=""
    for num in range(0,128,16):
        cipher = AES.new(keys.wbKey.decode('hex'), AES.MODE_CBC, iv)
        output += cipher.encrypt(input[num:num+16])
    return output

def DecryptParameterDataWithAES(input):
    iv = b"\x00" * BLOCK_SIZE
    output=b""
    for num in range(0,128,16):
        cipher = AES.new(keys.wbKey.decode('hex'), AES.MODE_CBC, iv)
        output += cipher.decrypt(input[num:num+16])
    return output

def applySamyGOKeyTransform(input):
    r = rijndael.rijndael(keys.transKey.decode('hex'), 16)
    return r.encrypt(input)
import sys
def generateServerHello(userId, pin):
    sha1 = hashlib.sha1()
    sha1.update(pin)
    pinHash = sha1.digest()
    aes_key = pinHash[:16]
    print("AES key: "+aes_key.encode('hex'))
    iv = "\x00" * BLOCK_SIZE
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(keys.publicKey.decode('hex'))
    print("AES encrypted: "+ encrypted.encode('hex'))
    swapped = EncryptParameterDataWithAES(encrypted)
    print("AES swapped: "+ swapped.encode('hex'))
    data = struct.pack(">I", len(userId)) + userId + swapped
    print("data buffer: "+data.encode('hex').upper())
    sha1 = hashlib.sha1()
    sha1.update(data)
    dataHash = sha1.digest()
    print("hash: "+dataHash.encode('hex'))
    serverHello = "\x01\x02" + "\x00"*5 + struct.pack(">I", len(userId)+132) + data + "\x00"*5
    return {"serverHello":serverHello, "hash":dataHash, "AES_key":aes_key}

def parseClientHello(clientHello, dataHash, aesKey, gUserId):
    USER_ID_POS = 15
    USER_ID_LEN_POS = 11
    GX_SIZE = 0x80
    data = clientHello.decode('hex')
    firstLen=struct.unpack(">I",data[7:11])[0]
    userIdLen=struct.unpack(">I",data[11:15])[0]
    destLen = userIdLen + 132 + SHA_DIGEST_LENGTH # Always equals firstLen????:)
    thirdLen = userIdLen + 132 
    print("thirdLen: "+str(thirdLen))
    print("hello: " + data.encode('hex'))
    dest = data[USER_ID_LEN_POS:thirdLen+USER_ID_LEN_POS] + dataHash
    print("dest: "+dest.encode('hex'))
    userId=data[USER_ID_POS:userIdLen+USER_ID_POS]
    print("userId: " + userId)
    pEncWBGx = data[USER_ID_POS+userIdLen:GX_SIZE+USER_ID_POS+userIdLen]
    print("pEncWBGx: " + pEncWBGx.encode('hex'))
    pEncGx = DecryptParameterDataWithAES(pEncWBGx)
    print("pEncGx: " + pEncGx.encode('hex'))
    iv = "\x00" * BLOCK_SIZE
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    pGx = cipher.decrypt(pEncGx)
    print("pGx: " + pGx.encode('hex'))
    bnPGx = int(pGx.encode('hex'),16)
    bnPrime = int(keys.prime,16)
    bnPrivateKey = int(keys.privateKey,16)
    secret = hex(pow(bnPGx, bnPrivateKey, bnPrime)).rstrip("L").lstrip("0x").decode('hex')
    print("secret: " + secret.encode('hex'))
    dataHash2 = data[USER_ID_POS+userIdLen+GX_SIZE:USER_ID_POS+userIdLen+GX_SIZE+SHA_DIGEST_LENGTH];
    print("hash2: " + dataHash2.encode('hex'))
    secret2 = userId + secret;
    print("secret2: " + secret2.encode('hex'))
    sha1 = hashlib.sha1()
    sha1.update(secret2)
    dataHash3 = sha1.digest()
    print("hash3: " + dataHash3.encode('hex'))
    if dataHash2 != dataHash3:
        print("Pin error!!!")
        return False
    print("Pin OK :)\n")
    flagPos = userIdLen + USER_ID_POS + GX_SIZE + SHA_DIGEST_LENGTH
    if ord(data[flagPos:flagPos+1]):
        print("First flag error!!!")
        return False
    flagPos = userIdLen + USER_ID_POS + GX_SIZE + SHA_DIGEST_LENGTH
    if struct.unpack(">I",data[flagPos+1:flagPos+5])[0]:
        print("Second flag error!!!")
        return False
    sha1 = hashlib.sha1()
    sha1.update(dest)
    dest_hash = sha1.digest()
    print("dest_hash: " + dest_hash.encode('hex'))
    finalBuffer = userId + gUserId + pGx + keys.publicKey.decode('hex') + secret
    sha1 = hashlib.sha1()
    sha1.update(finalBuffer)
    SKPrime = sha1.digest()
    print("SKPrime: " + SKPrime.encode('hex'))
    sha1 = hashlib.sha1()
    sha1.update(SKPrime+"\x00")
    SKPrimeHash = sha1.digest()
    print("SKPrimeHash: " + SKPrimeHash.encode('hex'))
    ctx = applySamyGOKeyTransform(SKPrimeHash[:16])
    return {"ctx":ctx, "SKPrime":SKPrime}

def generateServerAcknowledge(SKPrime):
    sha1 = hashlib.sha1()
    sha1.update(SKPrime+"\x01")
    SKPrimeHash = sha1.digest()
    return "0103000000000000000014"+SKPrimeHash.encode('hex').upper()+"0000000000"

def parseClientAcknowledge(clientAck, SKPrime):
    sha1 = hashlib.sha1()
    sha1.update(SKPrime+"\x02")
    SKPrimeHash = sha1.digest()
    tmpClientAck = "0104000000000000000014"+SKPrimeHash.encode('hex').upper()+"0000000000"
    return clientAck == tmpClientAck
