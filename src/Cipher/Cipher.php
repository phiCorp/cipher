<?php

namespace Cipher;

use Exception;

class Cipher
{
    /**
     * @var mixed $method The encryption/decryption method.
     */
    private $method;

    /**
     * @var mixed $key The encryption/decryption key.
     */
    private $key;

    /**
     * @var mixed $iv The initialization vector (IV) for encryption.
     */
    private $iv;

    /**
     * @var mixed $rsaPublicKey The RSA public key.
     */
    private $rsaPublicKey;

    /**
     * @var mixed $rsaPrivateKey The RSA private key.
     */
    private $rsaPrivateKey;

    /**
     * Cipher constructor.
     * @param mixed $method The encryption/decryption method.
     */
    private function __construct($method)
    {
        $this->method = $method;
    }

    /**
     * Create a new instance for AES encryption.
     *
     * @param string $mode The AES encryption mode (e.g., "CBC").
     * @param int $keySize The AES key size (e.g., 256).
     * @return Cipher A new Cipher instance for AES encryption.
     */
    public static function AES($mode = "CBC", $keySize = 256)
    {
        return new self("AES-$keySize-$mode");
    }

    /**
     * Create a new instance for RSA encryption/decryption.
     *
     * @param mixed $publicKey The RSA public key.
     * @param mixed $privateKey The RSA private key.
     * @return Cipher A new Cipher instance for RSA encryption/decryption.
     */
    public static function RSA($publicKey = null, $privateKey = null)
    {
        $instance = new self("RSA");
        $instance->rsaPublicKey = $publicKey;
        $instance->rsaPrivateKey = $privateKey;
        return $instance;
    }

    /**
     * Set the encryption/decryption key.
     *
     * @param mixed $key The encryption/decryption key.
     * @return $this The current Cipher instance.
     */
    public function key($key)
    {
        $this->key = $key;
        return $this;
    }

    /**
     * Set the RSA public key.
     *
     * @param mixed $key The RSA public key.
     * @return $this The current Cipher instance.
     */
    public function publicKey($key)
    {
        $this->rsaPublicKey = $key;
        return $this;
    }

    /**
     * Set the RSA private key.
     *
     * @param mixed $key The RSA private key.
     * @return $this The current Cipher instance.
     */
    public function privateKey($key)
    {
        $this->rsaPrivateKey = $key;
        return $this;
    }

    /**
     * Set the initialization vector (IV) for encryption.
     *
     * @param mixed $iv The initialization vector (IV).
     * @return $this The current Cipher instance.
     */
    public function iv($iv)
    {
        $this->iv = $iv;
        return $this;
    }

    /**
     * Encrypt the given plaintext using the specified algorithm.
     *
     * @param string $plaintext The plaintext to encrypt.
     * @param int $options Encryption options.
     * @param string|null $tag Encryption tag.
     * @param string $aad Additional authentication data.
     * @return string|false The encrypted ciphertext or false on failure.
     * @throws Exception If the method is not AES.
     */
    public function encrypt(string $plaintext, int $options = 0, &$tag = '', string $aad = "", int $tag_length = 16)
    {
        if (!str_starts_with($this->method, "AES")) {
            throw new Exception('The encrypt and decrypt methods only work on the AES algorithm');
        }
        return openssl_encrypt($plaintext, $this->method, $this->key, $options, $this->iv, $tag, $aad, $tag_length);
    }

    /**
     * Encrypt data using the RSA public key.
     *
     * @param mixed $data The data to encrypt.
     * @return string The encrypted data.
     */
    public function encryptPublic($data)
    {
        if (strlen($data) > 214) {
            openssl_public_encrypt(substr($data, 0, 214), $encrypted_data, $this->rsaPublicKey);
            $encrypted_data .= self::encryptPublic(substr($data, 214));
        } else {
            openssl_public_encrypt($data, $encrypted_data, $this->rsaPublicKey);
        }
        return $encrypted_data;
    }

    /**
     * Encrypt data using the RSA private key.
     *
     * @param mixed $data The data to encrypt.
     * @return string The encrypted data.
     */
    public function encryptPrivate($data)
    {
        if (strlen($data) > 214) {
            openssl_private_encrypt(substr($data, 0, 214), $encrypted_data, $this->rsaPrivateKey);
            $encrypted_data .= self::encryptPrivate(substr($data, 214));
        } else {
            openssl_private_encrypt($data, $encrypted_data, $this->rsaPrivateKey);
        }
        return $encrypted_data;
    }

    /**
     * Decrypt data using the RSA private key.
     *
     * @param mixed $data The data to decrypt.
     * @return string The decrypted data.
     */
    public function decryptPrivate($data)
    {
        if (strlen($data) > 512) {
            openssl_private_decrypt(substr($data, 0, 512), $decrypted_data, $this->rsaPrivateKey);
            $decrypted_data .= self::decryptPrivate(substr($data, 512));
        } else {
            openssl_private_decrypt($data, $decrypted_data, $this->rsaPrivateKey);
        }
        return $decrypted_data;
    }

    /**
     * Decrypt data using the RSA public key.
     *
     * @param mixed $data The data to decrypt.
     * @return bool|string The decrypted data or false on failure.
     */
    public function decryptPublic($data): bool|string
    {
        if (strlen($data) > 512) {
            openssl_public_decrypt(substr($data, 0, 512), $decrypted_data, $this->rsaPublicKey);
            $decrypted_data .= self::decryptPublic(substr($data, 512));
        } else {
            openssl_public_decrypt($data, $decrypted_data, $this->rsaPublicKey);
        }
        return $decrypted_data;
    }

    /**
     * Decrypt the given ciphertext using the specified algorithm.
     *
     * @param string $plaintext The ciphertext to decrypt.
     * @param int $options Decryption options.
     * @param string|null $tag Decryption tag.
     * @param string $aad Additional authentication data.
     * @return string|false The decrypted plaintext or false on failure.
     * @throws Exception If the method is not AES.
     */
    public function decrypt(string $plaintext, int $options = 0, string|null $tag = null, string $aad = "")
    {
        if (!str_starts_with($this->method, "AES")) {
            throw new Exception('The encrypt and decrypt methods only work on the AES algorithm');
        }
        return openssl_decrypt($plaintext, $this->method, $this->key, $options, $this->iv, $tag, $aad);
    }

    /**
     * Generate a random AES encryption key for the specified algorithm.
     *
     * @param string $algo The AES encryption algorithm (e.g., 'AES-256-CBC').
     * @param int $defaultKeyLengthDivide2 Default key length divided by 2.
     * @return string A random AES encryption key.
     */
    public static function AESKEY($algo = 'AES-256-CBC', $defaultKeyLengthDivide2 = 16)
    {
        $keyLengths  = ['aes-128-cbc' => 8, 'aes-128-cbc-hmac-sha1' => 8, 'aes-128-cbc-hmac-sha256' => 8, 'aes-128-ccm' => 8, 'aes-128-cfb' => 8, 'aes-128-cfb1' => 8, 'aes-128-cfb8' => 8, 'aes-128-ctr' => 8, 'aes-128-gcm' => 8, 'aes-128-ocb' => 8, 'aes-128-ofb' => 8, 'aes-128-xts' => 8, 'aes-192-cbc' => 12, 'aes-192-ccm' => 12, 'aes-192-cfb' => 12, 'aes-192-cfb1' => 12, 'aes-192-cfb8' => 12, 'aes-192-ctr' => 12, 'aes-192-gcm' => 12, 'aes-192-ocb' => 12, 'aes-192-ofb' => 12, 'aes-256-cbc' => 32, 'aes-256-cbc-hmac-sha1' => 16, 'aes-256-cbc-hmac-sha256' => 16, 'aes-256-ccm' => 16, 'aes-256-cfb' => 16, 'aes-256-cfb1' => 16, 'aes-256-cfb8' => 16, 'aes-256-ctr' => 16, 'aes-256-gcm' => 16, 'aes-256-ocb' => 16, 'aes-256-ofb' => 16, 'aes-256-xts' => 16,];
        return bin2hex(random_bytes($keyLengths[strtolower($algo)] ?? $defaultKeyLengthDivide2));
    }

    /**
     * Generate a random AES initialization vector (IV).
     *
     * @return string A random AES initialization vector (IV).
     */
    public static function AESIV()
    {
        return bin2hex(random_bytes(8));
    }

    /**
     * Generate RSA public and private keys.
     *
     * @param int $private_key_bits The number of bits for the RSA private key (e.g., 4096).
     * @return array An array containing the RSA public and private keys.
     */
    public static function RSAKEY($private_key_bits = 4096): array
    {
        $privateKey = openssl_pkey_new(["private_key_bits" => $private_key_bits, "private_key_type" => OPENSSL_KEYTYPE_RSA, "default_md" => "sha512", "digest_alg" => "sha512",]);
        $pubKey = openssl_pkey_get_details($privateKey)['key'];
        $privKey = openssl_pkey_get_private($privateKey);
        openssl_pkey_export($privKey, $priKey);
        return [$pubKey, $priKey];
    }

    /**
     * Perform bitwise XOR operation between data and a key.
     *
     * @param mixed $data The data to perform XOR on.
     * @param mixed $key The XOR key.
     * @return string The result of the XOR operation.
     */
    public static function XOR($data, $key)
    {
        $keyLength = strlen($key);
        $dataLength = strlen($data);
        $encrypted = '';
        for ($i = 0; $i < $dataLength; $i++) {
            $encrypted .= $data[$i] ^ $key[$i % $keyLength];
        }
        return $encrypted;
    }

    /**
     * Calculate the MD5 hash of the given data.
     *
     * @param mixed $data The data to hash.
     * @param bool $double_encode Whether to double-encode the hash.
     * @return string The MD5 hash of the data.
     */
    public static function md5($data, bool $double_encode = false)
    {
        return static::hash('md5', $data, $double_encode);
    }

    /**
     * Calculate the MD4 hash of the given data.
     *
     * @param mixed $data The data to hash.
     * @param bool $double_encode Whether to double-encode the hash.
     * @return string The MD4 hash of the data.
     */
    public static function md4($data, bool $double_encode = false)
    {
        return static::hash('md4', $data, $double_encode);
    }

    /**
     * Calculate the MD2 hash of the given data.
     *
     * @param mixed $data The data to hash.
     * @param bool $double_encode Whether to double-encode the hash.
     * @return string The MD2 hash of the data.
     */
    public static function md2($data, bool $double_encode = false)
    {
        return static::hash('md2', $data, $double_encode);
    }

    /**
     * Calculate the SHA-1 hash of the given data.
     *
     * @param mixed $data The data to hash.
     * @param bool $double_encode Whether to double-encode the hash.
     * @return string The SHA-1 hash of the data.
     */
    public static function sha1($data, bool $double_encode = false)
    {
        return static::hash('sha1', $data, $double_encode);
    }

    /**
     * Calculate the SHA-256 hash of the given data.
     *
     * @param mixed $data The data to hash.
     * @param bool $double_encode Whether to double-encode the hash.
     * @return string The SHA-256 hash of the data.
     */
    public static function sha256($data, bool $double_encode = false)
    {
        return static::hash('sha256', $data, $double_encode);
    }

    /**
     * Calculate the SHA-512 hash of the given data.
     *
     * @param mixed $data The data to hash.
     * @param bool $double_encode Whether to double-encode the hash.
     * @return string The SHA-512 hash of the data.
     */
    public static function sha512($data, bool $double_encode = false)
    {
        return static::hash('sha512', $data, $double_encode);
    }

    /**
     * Calculate the hash of the given data using the specified algorithm.
     *
     * @param string $algo The hashing algorithm (e.g., 'md5', 'sha1').
     * @param mixed $data The data to hash.
     * @param bool $double_encode Whether to double-encode the hash.
     * @return string The hashed data.
     */
    public static function hash($algo, $data, bool $double_encode = false)
    {
        $hashedValue = hash($algo, $data);
        if ($double_encode) {
            $hashedValue = hash($algo, $hashedValue);
        }
        return $hashedValue;
    }

    /**
     * Generate a bcrypt hash for the given value.
     *
     * @param string $value The value to hash.
     * @param int $cost The cost parameter for bcrypt hashing.
     * @return string The bcrypt hash of the value.
     */
    public static function bcrypt($value, int $cost = 12): string
    {
        return password_hash($value, PASSWORD_BCRYPT, ['cost' => $cost]);
    }

    /**
     * Verify a value against a bcrypt hash.
     *
     * @param string $password The password to verify.
     * @param string $hash The bcrypt hash to verify against.
     * @return bool True if the password matches the hash, false otherwise.
     */
    public static function bcrypt_verify($password, $hash): string
    {
        return password_verify($password, $hash);
    }

    /**
     * Base64 encode or decode data.
     *
     * @param mixed $data The data to encode or decode.
     * @return string|false The base64 encoded or decoded data.
     */
    public static function base64($data)
    {
        $encoded = base64_encode($data);
        if (base64_encode(base64_decode($data)) === $data) {
            $decoded = base64_decode($data);
            return $decoded;
        }
        return $encoded;
    }

    /**
     * Convert binary data to a hexadecimal string.
     *
     * @param mixed $data The binary data to convert.
     * @return string The hexadecimal representation of the binary data.
     */
    public static function hex($data)
    {
        return bin2hex($data);
    }

    /**
     * Convert a hexadecimal string to binary data.
     *
     * @param mixed $data The hexadecimal string to convert.
     * @return string The binary data.
     */
    public static function bin($data)
    {
        return hex2bin($data);
    }

    /**
     * Convert ASCII values to a string or vice versa.
     *
     * @param mixed $data The data to convert.
     * @param string $delimiter The delimiter for separating ASCII values.
     * @return string The converted data.
     */
    public static function ascii($data, $delimiter = ' ')
    {
        if (preg_match('/^(\d+' . preg_quote($delimiter) . ')+\d+$/', $data)) {
            $decoded = '';
            $values = explode($delimiter, $data);
            foreach ($values as $value) {
                $decoded .= chr($value);
            }
            return $decoded;
        }
        $encoded = '';
        $length = strlen($data);
        for ($i = 0; $i < $length; $i++) {
            $encoded .= ord($data[$i]) . $delimiter;
        }
        return rtrim($encoded, $delimiter);
    }
}
