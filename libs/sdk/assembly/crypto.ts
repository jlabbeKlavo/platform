/**
 * Environment definitions for compiling Klave Trustless Applications.
 * @module klave/sdk/crypto
 */

import { CryptoImpl, Key, MemoryType } from './crypto_impl';
import { SubtleCrypto } from './crypto_subtle';
import { CryptoAES } from './crypto_aes';
import { CryptoECDSA } from './crypto_ecc';
import { CryptoRSA } from './crypto_rsa';
import { CryptoSHA } from './crypto_sha';

export class Subtle extends SubtleCrypto { }
export class AES extends CryptoAES { };
export class ECDSA extends CryptoECDSA { };
export class RSA extends CryptoRSA { };
export class SHA extends CryptoSHA { };

export function getKey(keyName: string): Key | null {    
    if (CryptoImpl.keyExists(MemoryType.Persistent, keyName))
        return new Key(keyName);
    return null
}

export function getRandomValues(size: i32): u8[] {
    return CryptoImpl.getRandomBytes(size);
}

export class Utils {

    static convertToU8Array(input: Uint8Array): u8[] {
        let ret: u8[] = [];
        for (let i = 0; i < input.length; ++i)
            ret[i] = input[i];

        return ret;
    }

    static convertToUint8Array(input: u8[]): Uint8Array {
        let value = new Uint8Array(input.length);
        for (let i = 0; i < input.length; ++i) {
            value[i] = input[i];
        }

        return value;
    }

}
