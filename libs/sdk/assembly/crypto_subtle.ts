/**
 * Environment definitions for compiling Klave Trustless Applications.
 * @module klave/sdk/crypto
 */

import { decode, encode as b64encode } from 'as-base64/assembly';
import uuid from './uuid';
import { CryptoImpl, MemoryType, Key } from './crypto_impl';

class CryptoKey extends Key {
    algorithm: string;
    extractable: boolean;
    usages: string[];

    constructor(name: string, algorithm: string, extractable: boolean, usages: string[]) {
        super(name);
        this.algorithm = algorithm;
        this.extractable = extractable;
        this.usages = usages;
    }
}

export class SubtleCrypto {
    static generateKey(algorithm: string, algo_metadata: string, extractable: boolean, usages: string[]): CryptoKey | null
    {
        let key = CryptoImpl.generateKey(MemoryType.InMemory, "", algorithm, algo_metadata, extractable, usages);
        if (!key)
            return null;
        return new CryptoKey(key.name, algorithm, extractable, usages);
    }

    static encrypt(key: CryptoKey, encryption_info: string, clear_text: string): u8[]
    {
        return CryptoImpl.encrypt(key.name, encryption_info, clear_text);
    }
    
    static decrypt(key: CryptoKey, decryption_info: string, cipher_text: u8[]): string
    {
        return CryptoImpl.decrypt(key.name, decryption_info, cipher_text);
    }
    
    static sign(key: CryptoKey, signature_info: string, text: string): u8[]
    {
        return CryptoImpl.sign(key.name, signature_info, text);
    }
    
    static verify(key: CryptoKey, signature_info: string, text: string, signature: u8[]): boolean
    {
        return CryptoImpl.verify(key.name, signature_info, text, signature);
    }
    
    static digest(algorithm: string, hash_info: string, text: string): u8[]
    {
        return CryptoImpl.digest(algorithm, hash_info, text);
    }    
    static importKey(format: string, b64Data: string, algorithm: string, algo_metadata: string, extractable: boolean, usages: string[]): CryptoKey | null
    {
        let key = CryptoImpl.importKey(MemoryType.InMemory, "", format, b64Data, algorithm, algo_metadata, extractable, usages);
        if (!key)
            return null;
        return new CryptoKey(key.name, algorithm, extractable, usages);
    }

    static unwrapKey(decryptionKey: CryptoKey, decryption_info: string, format: string, b64Data: string, algorithm: string, algo_metadata: string, extractable: boolean, usages: string[]): CryptoKey | null
    {
        let key = CryptoImpl.unwrapKey(MemoryType.InMemory, decryptionKey.name, decryption_info, "", format, b64Data, algorithm, algo_metadata, extractable, usages);
        if (!key)
            return null;
        return new CryptoKey(key.name, algorithm, extractable, usages);
    }

    static exportKey(key: CryptoKey, format: string): u8[]
    {
        return CryptoImpl.exportKey(key.name, format);
    }        

    static getPublicKey(key: CryptoKey, format: string): u8[]
    {
        return CryptoImpl.getPublicKey(key.name, format);
    }        
}
