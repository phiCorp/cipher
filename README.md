
# Cipher

A tool for easier working with cryptography for PHP language


## Installation

Install Cipher with composer

```bash
composer require phicorp/cipher
```
    
## Features

- Easy to use
- Symmetric encryption and decryption with powerful AES algorithm
- Asymmetric encryption and decryption with RSA algorithm
- A variety of hash algorithms such as SHA and Bcrypt
- And more features
## Usage/Examples

* Symmetric encryption and decryption:

```php
$key = Cipher::AESKEY();
$iv = Cipher::AESIV();

$plaintext = 'Hello World!';

$ciphertext = encrypt($plaintext, $key, $iv);

$decryptedText = decrypt($ciphertext, $key, $iv);

echo "Original: $plaintext\n";
echo "Encrypted: $ciphertext\n";
echo "Decrypted: $decryptedText\n";
```

Or

```php
$key = Cipher::AESKEY();
$iv = Cipher::AESIV();

$plaintext = 'Hello World!';

$ciphertext = Cipher::AES()->key($key)->iv($iv)->encrypt($plaintext);

$decryptedText = Cipher::AES()->key($key)->iv($iv)->decrypt($ciphertext);

echo "Original: $plaintext\n";
echo "Encrypted: $ciphertext\n";
echo "Decrypted: $decryptedText\n";
```

* GCM Mode symmetric encryption and decryption

```php
$key = Cipher::AESKEY("AES-256-GCM");
$iv = Cipher::AESIV();
$tag = null;

$plaintext = 'Hello World!';

$ciphertext = Cipher::AES('GCM')->key($key)->iv($iv)->encrypt($plaintext, 0, $tag);

$decryptedText = Cipher::AES('GCM')->key($key)->iv($iv)->decrypt($ciphertext, 0, $tag);

echo "Original: $plaintext\n";
echo "Encrypted: $ciphertext\n";
echo "Decrypted: $decryptedText\n";
```
-----------
* Examples for asymmetric encryption and decryption
```php
[$publicKey, $privateKey] = Cipher::RSAKEY();

$plaintext = 'hello world!';

$ciphertext = RSA($publicKey, $privateKey)->encryptPublic($plaintext);
$decryptedText = RSA($publicKey, $privateKey)->decryptPrivate($ciphertext);

echo "Original: $plaintext\n";
echo "Encrypted: $ciphertext\n";
echo "Decrypted: $decryptedText\n";

// You can also use it in this way

[$publicKey, $privateKey] = Cipher::RSAKEY();

$plaintext = 'hello world!';

$ciphertext = Cipher::RSA()->privateKey($privateKey)->encryptPrivate($plaintext);
$decryptedText = RSA()->publicKey($publicKey)->decryptPublic($ciphertext);

echo "Original: $plaintext\n";
echo "Encrypted: $ciphertext\n";
echo "Decrypted: $decryptedText\n";
```

-----------

* Example of using hash functions
```php
sha512('Hello World!');
//output: 861844d6704e...
sha256('Hello World!');
//output: 7f83b1657ff1...
```

```php
$hash = bcrypt('password', 15);

var_dump(bcrypt_verify('password', $hash));
// output: true
```

## Authors

- [@thephibonacci](https://www.github.com/thephibonacci)


## License

[MIT](https://choosealicense.com/licenses/mit/)

