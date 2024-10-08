import { decode, encode as b64encode } from 'as-base64/assembly';
import uuid from '../uuid';
import { Crypto, Notifier } from '@klave/sdk';
import * as idlV1 from "./crypto_subtle_idl_v1"
import { Result } from '..';

//Persistent Crypto operations (i.e. output that are stored in the ledger)
// @ts-ignore: decorator
@external("env", "generate_key_and_persist")
declare function wasm_generate_key_and_persist(key_name: ArrayBuffer, algorithm: i32, algo_metadata: ArrayBuffer, extractable: i32, usages: ArrayBuffer, usages_size: i32): i32;
// @ts-ignore: decorator
@external("env", "import_key_and_persist")
declare function wasm_import_key_and_persist(key_name: ArrayBuffer, key_format: i32, key_data: ArrayBuffer, key_data_size: i32, algorithm: i32, algo_metadata: ArrayBuffer, extractable: i32, usages: ArrayBuffer, usages_size: i32): i32;
// @ts-ignore: decorator
@external("env", "unwrap_key_and_persist")
declare function wasm_unwrap_key_and_persist(decryption_key_name: ArrayBuffer, unwrap_algo_id: i32, unwrap_metadata: ArrayBuffer, key_name_to_import: ArrayBuffer, key_format: i32, wrapped_data: ArrayBuffer, wrapped_data_size: i32, key_gen_algo_id: i32, key_gen_metadata: ArrayBuffer, extractable: i32, usages: ArrayBuffer, usages_size: i32): i32;


//In-memory Crypto operations
// @ts-ignore: decorator
@external("env", "key_exists")
declare function wasm_key_exists(key_name: ArrayBuffer): boolean;
// @ts-ignore: decorator
@external("env", "encrypt")
declare function wasm_encrypt(key_name: ArrayBuffer, algorithm: i32, encryption_info: ArrayBuffer, clear_text: ArrayBuffer, clear_text_size: i32, cipher_text: ArrayBuffer, cipher_text_size: i32): i32;
// @ts-ignore: decorator
@external("env", "decrypt")
declare function wasm_decrypt(key_name: ArrayBuffer, algorithm: i32, encryption_info: ArrayBuffer, cipher_text: ArrayBuffer, cipher_text_size: i32, clear_text: ArrayBuffer, clear_text_size: i32): i32;
// @ts-ignore: decorator
@external("env", "generate_key")
declare function wasm_generate_key(key_name: ArrayBuffer, algorithm: i32, algo_metadata: ArrayBuffer, extractable: i32, usages: ArrayBuffer, usages_size: i32): i32;
// @ts-ignore: decorator
@external("env", "import_key")
declare function wasm_import_key(key_name: ArrayBuffer, key_format: i32, key_data: ArrayBuffer, key_data_size: i32, algorithm: i32, algo_metadata: ArrayBuffer, extractable: i32, usages: ArrayBuffer, usages_size: i32): i32;
// @ts-ignore: decorator
@external("env", "export_key")
declare function wasm_export_key(key_name: ArrayBuffer, key_format: i32, key: ArrayBuffer, key_size: i32): i32;
// @ts-ignore: decorator
@external("env", "get_public_key")
declare function wasm_get_public_key(key_name: ArrayBuffer, key_format: i32, result: ArrayBuffer, result_size: i32): i32;
// @ts-ignore: decorator
@external("env", "sign")
declare function wasm_sign(key_name: ArrayBuffer, algorithm: i32, signature_metadata: ArrayBuffer, text: ArrayBuffer, text_size: i32, signature: ArrayBuffer, signature_size: i32): i32;
// @ts-ignore: decorator
@external("env", "verify")
declare function wasm_verify(key_name: ArrayBuffer, algorithm: i32, signature_metadata: ArrayBuffer, text: ArrayBuffer, text_size: i32, signature: ArrayBuffer, signature_size: i32): i32;
// @ts-ignore: decorator
@external("env", "digest")
declare function wasm_digest(algorithm: i32, hash_info: ArrayBuffer, text: ArrayBuffer, text_size: i32, digest: ArrayBuffer, digest_size: i32): i32;
// @ts-ignore: decorator
@external("env", "unwrap_key")
declare function wasm_unwrap_key(decryption_key_name: ArrayBuffer, unwrap_algo_id: i32, unwrap_metadata: ArrayBuffer, key_name_to_import: ArrayBuffer, key_format: i32, wrapped_data: ArrayBuffer, wrapped_data_size: i32, key_gen_algo_id: i32, key_gen_metadata: ArrayBuffer, extractable: i32, usages: ArrayBuffer, usages_size: i32): i32;
// @ts-ignore: decorator
@external("env", "wrap_key")
declare function wasm_wrap_key(key_name_to_export: ArrayBuffer, key_format: i32, wrapping_key_name: ArrayBuffer, wrap_algo_id: i32, wrap_metadata: ArrayBuffer, key: ArrayBuffer, key_size: i32): i32;

// @ts-ignore: decorator
@external("env", "get_random_bytes")
declare function wasm_get_random_bytes(bytes: ArrayBuffer, size: i32): i32;

export class KeyFormatWrapper 
{
    format!: idlV1.key_format;
}

export class Key {
    name: string;

    constructor(keyName: string) {
        if (keyName.length !== 0 && keyName !== "")
            this.name = keyName;
        else {
            const rnds = CryptoImpl.getRandomBytes(16);
            // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
            unchecked(rnds[6] = (rnds[6] & 0x0f) | 0x40);
            unchecked(rnds[8] = (rnds[8] & 0x3f) | 0x80);

            const rndsArray = new Uint8Array(rnds.length);
            rndsArray.set(rnds);
            this.name = uuid(rndsArray);
        }
    }
}

export const enum MemoryType {
    Persistent = 0,
    InMemory = 1,
};

export class CryptoImpl {

    static usage(input: string): i32 {
        if (input === "encrypt")
            return 0;
        if (input === "decrypt")
            return 1;
        if (input === "sign")
            return 2;
        if (input === "verify")
            return 3;
        if (input === "derive_key")
            return 4;
        if (input === "derive_bits")
            return 5;
        if (input === "wrap_key")
            return 6;
        if (input === "unwrap_key")
            return 7;
        return -1;
    }

    static keyExists(key_name: string): boolean {        
        let result = false;
        result = wasm_key_exists(String.UTF8.encode(key_name, true));
        return result;
    }

    static generateKeyAndPersist(keyName: string, algorithm: u32, algoMetadata: ArrayBuffer, extractable: boolean, usages: string[]): Result<Key,Error>
    {
        const local_usages = new Uint8Array(usages.length);
        for(let i = 0; i < usages.length; i++)
        {
            local_usages[i] = this.usage(usages[i]);
        }

        const key = new Key(keyName);
        let result = 0;
        result = wasm_generate_key_and_persist(
                String.UTF8.encode(key.name, true), algorithm, algoMetadata, extractable?1:0, local_usages.buffer, local_usages.length);
        if (result < 0)
            return {data: null, err: new Error("Failed to generate key")};

        return {data: key, err: null};
    }

    static generateKey(algorithm: u32, algoMetadata: ArrayBuffer, extractable: boolean, usages: string[]): Result<Key,Error>
    {
        const local_usages = new Uint8Array(usages.length);
        for(let i = 0; i < usages.length; i++)
        {
            local_usages[i] = this.usage(usages[i]);
        }

        const key = new Key("");
        let result = 0;
        result = wasm_generate_key(
                String.UTF8.encode(key.name, true), algorithm, algoMetadata, extractable?1:0, local_usages.buffer, local_usages.length);
        if (result < 0)
            return {data: null, err: new Error("Failed to generate key")};

        return {data: key, err: null};
    }

    static encrypt(keyName: string, algorithm: u32, algoMetadata: ArrayBuffer, clearText: ArrayBuffer): Result<ArrayBuffer, Error>
    {
        let k = String.UTF8.encode(keyName, true);
        let value = new Uint8Array(64);
        let result = wasm_encrypt(k, algorithm, algoMetadata, clearText, clearText.byteLength, value.buffer, value.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to encrypt")};
        if (result > value.byteLength) {
            // buffer not big enough, retry with a properly sized one
            value = new Uint8Array(result);
            result = wasm_encrypt(k, algorithm, algoMetadata, clearText, clearText.byteLength, value.buffer, value.byteLength);
            if (result < 0)
                return {data: null, err: new Error("Failed to encrypt")};
        }
        return {data: value.buffer.slice(0, result), err: null};
    }
    
    static decrypt(keyName: string, algorithm: u32, algoMetadata: ArrayBuffer, cipherText: ArrayBuffer): Result<ArrayBuffer, Error>
    {
        let k = String.UTF8.encode(keyName, true);
        let value = new Uint8Array(64);
        let result = wasm_decrypt(k, algorithm, algoMetadata, cipherText, cipherText.byteLength, value.buffer, value.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to decrypt")};
        if (result > value.byteLength) {
            // buffer not big enough, retry with a properly sized one
            value = new Uint8Array(result);
            result = wasm_decrypt(k, algorithm, algoMetadata, cipherText, cipherText.byteLength, value.buffer, value.byteLength);
            if (result < 0)
                return {data: null, err: new Error("Failed to decrypt")};
        }
        return {data: value.buffer.slice(0, result), err: null};
    }
    
    static sign(keyName: string, algorithm: u32, algoMetadata: ArrayBuffer, data: ArrayBuffer): Result<ArrayBuffer, Error>
    {
        let k = String.UTF8.encode(keyName, true);
        let value = new Uint8Array(64);
        let result = wasm_sign(k, algorithm, algoMetadata, data, data.byteLength, value.buffer, value.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to sign")};
        if (result > value.byteLength) {
            // buffer not big enough, retry with a properly sized one
            value = new Uint8Array(result);
            result = wasm_sign(k, algorithm, algoMetadata, data, data.byteLength, value.buffer, value.byteLength);
            if (result < 0)
                return {data: null, err: new Error("Failed to sign")};
        }
        return {data: value.buffer.slice(0, result), err: null};
    }
    
    static verify(keyName: string, algorithm: u32, algoMetadata: ArrayBuffer, data: ArrayBuffer, signature: ArrayBuffer): Result<boolean, Error>
    {
        let k = String.UTF8.encode(keyName, true);
        let result = wasm_verify(k, algorithm, algoMetadata, data, data.byteLength, signature, signature.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to verify")};
        return {data: result != 0, err: null};
    }
    
    static digest(algorithm: idlV1.hash_algorithm, hashInfo: ArrayBuffer, text: ArrayBuffer): Result<ArrayBuffer, Error>
    {
        let value = new Uint8Array(32);
        let result = wasm_digest(algorithm, hashInfo, text, text.byteLength, value.buffer, value.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to digest")};
        if (result > value.byteLength) {
            // buffer not big enough, retry with a properly sized one
            value = new Uint8Array(result);
            result = wasm_digest(algorithm, hashInfo, text, text.byteLength, value.buffer, value.byteLength);
            if (result < 0)
                return {data: null, err: new Error("Failed to digest")};
        }
        return {data: value.buffer.slice(0, result), err: null};
    }

    static importKey(format: u32, keyData: ArrayBuffer, algorithm: u32, algo_metadata: ArrayBuffer, extractable: boolean, usages: string[]): Result<Key, Error>
    {
        const key = new Key("");

        const local_usages = new Uint8Array(usages.length);
        for(let i = 0; i < usages.length; i++)
        {
            local_usages[i] = this.usage(usages[i]);
        }

        let result = wasm_import_key(String.UTF8.encode(key.name, true), format, keyData, keyData.byteLength, algorithm, algo_metadata, extractable ? 1 : 0, local_usages.buffer, local_usages.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to import key")};

        return {data: key, err: null};
    }

    static exportKey(keyName: string, format: u32): Result<ArrayBuffer, Error>
    {
        let key = new Uint8Array(32);
        let result = wasm_export_key(String.UTF8.encode(keyName, true), format, key.buffer, key.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to export key")};
        if (result > key.byteLength) {
            // buffer not big enough, retry with a properly sized one
            key = new Uint8Array(result);
            result = wasm_export_key(String.UTF8.encode(keyName, true), format, key.buffer, key.byteLength);
            if (result < 0)
                return {data: null, err: new Error("Failed to export key")};
        }
        return {data: key.buffer.slice(0, result), err: null};
    }

    static unwrapKey(decryptionKeyName: string, unwrap_algo_id: u32, unwrap_metadata: ArrayBuffer, format: u32, wrapped_key: ArrayBuffer, key_gen_algorithm: u32, key_gen_algo_metadata: ArrayBuffer, extractable: boolean, usages: string[]): Result<Key, Error>
    {
        const key = new Key("");
        const local_usages = new Uint8Array(usages.length);
        for(let i = 0; i < usages.length; i++)
        {
            local_usages[i] = this.usage(usages[i]);
        }

        let result = wasm_unwrap_key(String.UTF8.encode(decryptionKeyName, true), unwrap_algo_id, unwrap_metadata, String.UTF8.encode(key.name, true), format, wrapped_key, wrapped_key.byteLength, key_gen_algorithm, key_gen_algo_metadata, extractable ? 1 : 0, local_usages.buffer, local_usages.byteLength);
        
        if (result < 0)
            return {data: null, err: new Error("Failed to unwrap key")};

        return {data: key, err: null};
    }

    static wrapKey(encryptionKeyName: string, algorithm: u32, algo_metadata: ArrayBuffer, key_name: string, format: u32): Result<ArrayBuffer, Error>
    {
        let key = new Uint8Array(32);
        let result = wasm_wrap_key(String.UTF8.encode(key_name, true), format, String.UTF8.encode(encryptionKeyName, true), algorithm, algo_metadata, key.buffer, key.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to wrap key")};
        if (result > key.byteLength) {
            // buffer not big enough, retry with a properly sized one
            key = new Uint8Array(result);
            result = wasm_wrap_key(String.UTF8.encode(key_name, true), format, String.UTF8.encode(encryptionKeyName, true), algorithm, algo_metadata, key.buffer, key.byteLength);
            if (result < 0)
                return {data: null, err: new Error("Failed to wrap key")};
        }
        return {data: key.buffer.slice(0, result), err: null};
    }

    static getPublicKey(keyName: string, format: u32): Result<ArrayBuffer, Error>
    {
        let key = new Uint8Array(32);
        let result = wasm_get_public_key(String.UTF8.encode(keyName, true), format, key.buffer, key.byteLength);
        if (result < 0)
            return {data: null, err: new Error("Failed to get public key")};
        if (result > key.byteLength) {
            // buffer not big enough, retry with a properly sized one
            key = new Uint8Array(result);
            result = wasm_get_public_key(String.UTF8.encode(keyName, true), format, key.buffer, key.byteLength);
            if (result < 0)
                return {data: null, err: new Error("Failed to get public key")};
        }
        return {data: key.buffer.slice(0, result), err: null};
    }

    static getRandomBytes(size: i32): u8[] {
        const value = new Uint8Array(size);
        const result = wasm_get_random_bytes(value.buffer, value.byteLength);
        const ret: u8[] = []
        if (result < 0)
            return ret; // todo : report error
        for (let i = 0; i < size; ++i)
            ret[i] = value[i];
        return ret;
    }
}