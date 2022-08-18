import crypto from 'crypto';
// YOU need to "npm install bn.js" 
import BN from 'bn.js';
import {AES_128_Transform} from "./aes.js";
import {keys} from "./keys";

// Inspirations:
// https://github.com/sectroyer/SmartCrypto/blob/master/SmartCrypto/crypto.c
// https://github.com/McKael/smartcrypto/blob/736f9f22e25502a5d9680001fbb2f4ee9c6a5d8d/smartcrypto.go

const null_iv = Buffer.from('00000000000000000000000000000000', 'hex');

function encryptHex(key, data, mode, iv, padding) {
    const keyBytes = typeof key === 'string' ? Buffer.from(key, 'hex') : key;
    const dataBytes = typeof data === 'string' ? Buffer.from(data, 'hex') : data;
    const cipher = crypto.createCipheriv(mode, keyBytes, iv);
    if (padding === false) {
        cipher.setAutoPadding(false);
    }
    cipher.write(dataBytes);
    cipher.end();
    return cipher.read();
}

export function encryptHexCbc(key, data, padding) {
    return encryptHex(key, data, 'aes-128-cbc', null_iv, padding);
}

export function encryptHexEcb(key, data) {
    return encryptHex(key, data, 'aes-128-ecb', null);
}

function decryptHex(key, data, mode, iv, padding) {
    const keyBytes = typeof key === 'string' ? Buffer.from(key, 'hex') : key;
    const dataBytes = typeof data === 'string' ? Buffer.from(data, 'hex') : data;
    const decipher = crypto.createDecipheriv(mode, keyBytes, iv);
    if (padding === false) {
        decipher.setAutoPadding(false);
    }
    decipher.write(dataBytes);
    decipher.end();
    return decipher.read();
}

export function decryptHexCbc(key, data, padding) {
    return decryptHex(key, data, 'aes-128-cbc', null_iv, padding);
}

export function decryptHexEcb(key, data, padding) {
    return decryptHex(key, data, 'aes-128-ecb', null, padding);
}

function bufferAppendUInt32BE(data, value) {
    const temp = Buffer.alloc(4);
    temp.writeUInt32BE(value, 0);
    return Buffer.concat([data, temp]);
}

function bufferAppendHex(data, bin) {
    const dataBytes = typeof bin === 'string' ? Buffer.from(bin, 'hex') : bin;
    return Buffer.concat([data, dataBytes]);
}

function bufferAppendString(data, str) {
    const temp = Buffer.alloc(str.length);
    temp.write(str, 0);
    return Buffer.concat([data, temp]);
}

/**
 * Calculates the SHA1 digest from an input buffer 
 * @param buffer {Buffer|Uint8Array}
 * @returns {Uint8Array}
 */
export function sha1Digest(buffer) {
    const hash = crypto.createHash('sha1');
    hash.write(buffer);
    hash.end();
    return hash.digest();
}

/**
 * Generates a server Hello
 * @param {string} userId
 * @param {string} pin
 * @returns {{ userId: string, hash: string, generator: string, key: string }}
 */
export function generateServerHello(userId, pin) {
    if (!userId || userId.length < 1 || userId.length > 96) {
        throw new Error(`invalid userID size (${(userId || 0).length})`);
    }

    if (!pin || pin.length !== 4) {
        throw new Error(`Invalid pin size (${(pin || 0).length})`);
    }
    
    const pinHash = sha1Digest(Buffer.from(pin, 'utf8'));
    const key = pinHash.subarray(0, 16);
    const encrypted = encryptHexCbc(key, keys.publicKey);
    const swapped = encryptHexEcb(keys.wbKey, encrypted).subarray(0, 128);

    let dataBuf = Buffer.alloc(0);
    dataBuf = bufferAppendUInt32BE(dataBuf, userId.length);
    dataBuf = bufferAppendString(dataBuf, userId);
    dataBuf = bufferAppendHex(dataBuf, swapped);

    const hash = bytesToHex(sha1Digest(dataBuf));
    
    let serverHelloBuf = Buffer.alloc(0);
    serverHelloBuf = bufferAppendHex(serverHelloBuf, '01020000000000');
    serverHelloBuf = bufferAppendUInt32BE(serverHelloBuf, dataBuf.length);
    serverHelloBuf = bufferAppendHex(serverHelloBuf, dataBuf);
    serverHelloBuf = bufferAppendHex(serverHelloBuf, '0000000000');

    const expectedLength = 10 + 1 + (4 + userId.length + 128) + 5;
    if (serverHelloBuf.length !== expectedLength) {
        throw new Error(`Generated invalid server hello`);
    }
    
    const generator = serverHelloBuf.toString('hex').toUpperCase();
    return {
        userId,
        generator,
        hash,
        key: bytesToHex(key)
    };
}

class DataReader {

    /**
     * Creates a new reader
     * @param {Uint8Array} bytes
     */
    constructor(bytes) {
        /**
         * @type {Buffer}
         * @private
         */
        this.buffer = bytesToBuffer(bytes);

        /**
         * @type {number}
         * @private
         */
        this.offset = 0;
    }

    get length() {
        return this.buffer.length;
    }

    /**
     * @param {number} count
     * @return {Uint8Array}
     */
    readBytes(count) {
        this.ensure(count);
        const result = bufferToBytes(this.buffer, this.offset, count);
        this.offset += count;
        return result;
    }

    /**
     * Reads a BigEndian number
     * @return {number}
     */
    readUInt32BE() {
        this.ensure(4);
        const result = this.buffer.readUInt32BE(this.offset);
        this.offset += 4;
        return result;
    }

    readByte() {
        this.ensure(1);
        const byte = this.buffer.readUInt8(this.offset);
        this.offset++;
        return byte;
    }

    /**
     * Ensure has N available bytes to read
     * @private
     * @param {number} count
     */
    ensure(count) {
        const remaining = this.length - this.offset;
        if (remaining < count) {
            throw new Error('EOS');
        }
    }
}

/**
 * Parses a client hello and returns a ctx
 * @param data {String}
 * @param serverHello {{hash: string, userId: string, key: string}}
 * @returns {{skPrime: Uint8Array, ctx: string, skPrimeHash: string}|null}
 */
export function parseClientHelloNew(data, serverHello) {
    const gxSize = 0x80;
    const reader = new DataReader(hexToBytes(data));

    if (reader.length < 164) {
        console.log("ClientHello string looks too short");
        return null;
    }

    const header = reader.readBytes(7);
    if (bytesToHex(header) !== '01010000000000') {
        console.log("ClientHello has invalid header");
        return null;
    }
    
    const payloadSize = reader.readUInt32BE();
    const length = reader.readUInt32BE();
    if (length + 152 !== payloadSize) {
        console.log("ClientHello has invalid client ID lenght");
        return null;
    }
    
    const clientUserId = bytesToStr(reader.readBytes(length));
    if (clientUserId !== serverHello.userId) {
        console.log("ClientHello has invalid client ID value");
        return null;
    }
    
    const encWBGx = reader.readBytes(gxSize);
    const encGx = decryptHexEcb(keys.wbKey, encWBGx, false);
    const gx = decryptHexCbc(serverHello.key, encGx, false);

    const bnGx = new BN(bytesToHex(gx), 16);
    const bnPrivate = new BN(keys.privateKey, 16);
    const bnPrime = new BN(keys.prime, 16);
    const secret = new Uint8Array(bnGx.toRed(BN.red(bnPrime)).redPow(bnPrivate).fromRed().toArray());
    
    const clientHash = bytesToHex(reader.readBytes(20));
    const flag1 = reader.readByte();
    if (flag1 !== 0) {
        console.log('Client Hello parsing failed: flag #1 is not null');
        return null;
    }

    const flag2 = reader.readUInt32BE();
    if (flag2 !== 0) {
        console.log('Client Hello parsing failed: flag #2 is not null');
        return null;
    }

    const clientIdBytes = strToBytes(serverHello.userId);
    const dataX = Buffer.concat([clientIdBytes, secret]);
    const calculatedHash = bytesToHex(sha1Digest(dataX));
    if (calculatedHash !== clientHash) {
        console.log('Bad PIN');
        return null;
    }

    const skPrime = sha1Digest(Buffer.concat([
        clientIdBytes,
        clientIdBytes,
        gx,
        hexToBytes(keys.publicKey),
        secret
    ]));

    // Append byte 0x00 and hash
    const skPrimeHash = sha1Digest(Buffer.concat([skPrime, hexToBytes('00')]));
    bytesToHex(skPrimeHash)

    const ctx = new Uint8Array(16);
    AES_128_Transform(3, hexToBytes(keys.transKey), skPrimeHash, ctx);
    
    return {
        skPrime,
        ctx: bytesToHex(ctx),
        skPrimeHash: bytesToHex(skPrimeHash)
    }
}

/**
 * Converts a hex string into a buffer 
 * @param hexString {String}
 * @returns {Uint8Array}
 */
export function hexToBytes(hexString) {
    return bufferToBytes(Buffer.from(hexString, 'hex'));
}

/**
 * Converts a buffer into a byte array
 * @param {Buffer} buffer
 * @param {number?} offset
 * @param {number?} count
 * @return {Uint8Array}
 */
export function bufferToBytes(buffer, offset, count) {
    if (typeof offset === 'undefined') {
        offset = 0;
    }
    if (typeof count === 'undefined') {
        count = buffer.length;
    }
    const array = new Uint8Array(count);
    for (let i = 0; i < count; i++) {
        array[i] = buffer[i + offset];
    }
    return array;
}

/**
 * Converts a buffer into a byte array
 * @param {Uint8Array} bytes
 * @return {Buffer}
 */
export function bytesToBuffer(bytes) {
    return Buffer.from(bytes);
}

/**
 * Converts a utf-8 string into a buffer
 * @param str {String}
 * @returns {Uint8Array}
 */
export function strToBytes(str) {
    return bufferToBytes(Buffer.from(str, 'utf8'));
}

/**
 * Converts a buffer into an hex string 
 * @param bytes {Uint8Array}
 * @returns {string}
 */
export function bytesToHex(bytes) {
    return bytesToBuffer(bytes).toString('hex');
}

/**
 * Converts a buffer into an utf-8 string
 * @param buffer {Buffer|Uint8Array}
 * @returns {string}
 */
export function bytesToStr(buffer) {
    if (buffer instanceof Uint8Array) {
        buffer = bytesToBuffer(buffer);
    }
    return buffer.toString('utf8');
}

/**
 * Generate a server acknowledge
 * @param skPrime {Uint8Array}
 * @returns {string}
 */
export function generateServerAcknowledge(skPrime) {
    const prefix = '0103000000000000000014';
    const hash = bytesToHex(sha1Digest(Buffer.concat([skPrime, hexToBytes('01')])));
    const suffix = '0000000000';
    return `${prefix}${hash}${suffix}`.toUpperCase();
}

/**
 * Parses a client acknowledge data
 * @param clientAck {string}
 * @param skPrime {Uint8Array}
 * @returns {boolean}
 */
export function parseClientAcknowledge(clientAck, skPrime) {
    if (clientAck.length < 72) {
        throw new Error("incorrect client acknowledge length");
    }
    const expectedClientAckData = bytesToHex(sha1Digest(Buffer.concat([skPrime, hexToBytes('02')]))) + "0000000000";
    return expectedClientAckData === clientAck.substring(22).toLowerCase();
}
