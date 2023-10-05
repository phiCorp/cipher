<?php

use Cipher\Cipher;

if (!function_exists('encrypt')) {
    /**
     * Encrypts a plaintext using AES encryption.
     *
     * @param string $plaintext The plaintext to encrypt.
     * @param string $key The encryption key.
     * @param string $iv The initialization vector (IV).
     * @param string $mode The encryption mode (default is "CBC").
     * @param int $keySize The key size in bits (default is 256).
     * @return string The encrypted ciphertext.
     */
    function encrypt($plaintext, $key, $iv, $mode = "CBC", $keySize = 256)
    {
        return Cipher::AES($mode, $keySize)->key($key)->iv($iv)->encrypt($plaintext);
    }
}

if (!function_exists('decrypt')) {
    /**
     * Decrypts a ciphertext using AES decryption.
     *
     * @param string $ciphertext The ciphertext to decrypt.
     * @param string $key The decryption key.
     * @param string $iv The initialization vector (IV).
     * @param string $mode The encryption mode (default is "CBC").
     * @param int $keySize The key size in bits (default is 256).
     * @return string The decrypted plaintext.
     */
    function decrypt($ciphertext, $key, $iv, $mode = "CBC", $keySize = 256)
    {
        return Cipher::AES($mode, $keySize)->key($key)->iv($iv)->decrypt($ciphertext);
    }
}

if (!function_exists('AES')) {
    /**
     * Creates an AES encryption instance.
     *
     * @param string $mode The encryption mode (default is "CBC").
     * @param int $keySize The key size in bits (default is 256).
     * @return Cipher\Cipher The AES encryption instance.
     */
    function AES($mode = "CBC", $keySize = 256)
    {
        return Cipher::AES($mode, $keySize);
    }
}

if (!function_exists('RSA')) {
    /**
     * Creates an RSA encryption instance.
     *
     * @param string|null $publicKey The public key (optional).
     * @param string|null $privateKey The private key (optional).
     * @return Cipher\Cipher The RSA encryption instance.
     */
    function RSA($publicKey = null, $privateKey = null)
    {
        return Cipher::RSA($publicKey, $privateKey);
    }
}

if (!function_exists('sha256')) {
    /**
     * Computes the SHA-256 hash of the given data.
     *
     * @param string $data The input data to hash.
     * @param bool $double_encode Whether to double-encode the result (default is false).
     * @return string The SHA-256 hash.
     */
    function sha256($data, bool $double_encode = false)
    {
        return Cipher::sha256($data, $double_encode);
    }
}

if (!function_exists('sha512')) {
    /**
     * Computes the SHA-512 hash of the given data.
     *
     * @param string $data The input data to hash.
     * @param bool $double_encode Whether to double-encode the result (default is false).
     * @return string The SHA-512 hash.
     */
    function sha512($data, bool $double_encode = false)
    {
        return Cipher::sha512($data, $double_encode);
    }
}

if (!function_exists('base64')) {
    /**
     * Base64 encode or decode data.
     *
     * @param mixed $data The data to encode or decode.
     * @return string|false The base64 encoded or decoded data.
     */
    function base64($data)
    {
        return Cipher::base64($data);
    }
}

if (!function_exists('ascii')) {
    /**
     * Convert ASCII values to a string or vice versa.
     *
     * @param mixed $data The data to convert.
     * @param string $delimiter The delimiter for separating ASCII values.
     * @return string The converted data.
     */
    function ascii($data, $delimiter = ' ')
    {
        return Cipher::ascii($data, $delimiter);
    }
}

if (!function_exists('bcrypt')) {
    /**
     * Hashes a value using the Bcrypt algorithm.
     *
     * @param string $value The value to hash.
     * @param int $cost The cost factor (default is 12).
     * @return string The Bcrypt hash of the value.
     */
    function bcrypt($value, int $cost = 12)
    {
        return Cipher::bcrypt($value,  $cost);
    }
}

if (!function_exists('bcrypt_verify')) {
    /**
     * Verifies a password against a Bcrypt hash.
     *
     * @param string $password The password to verify.
     * @param string $hash The Bcrypt hash to compare against.
     * @return bool True if the password matches the hash, false otherwise.
     */
    function bcrypt_verify($password, $hash)
    {
        return Cipher::bcrypt_verify($password, $hash);
    }
}
