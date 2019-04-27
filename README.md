# Crystal-ECDSA

A Crystal C binding for the ECDSA functionality of OpenSSL that focuses specifically on secp256k1.
This library requires you to have OpenSSL installed.

Thanks to Eric Davis for his ecies library and to John Feras for his adaptation of Eric's code for this library.

[![Build Status](https://travis-ci.org/SushiChain/crystal-ecdsa.svg?branch=master)](https://travis-ci.org/SushiChain/crystal-ecdsa)

## Installation

1. Add the dependency to your `shard.yml`:
```yaml
dependencies:
  crystal-ecdsa:
    github: sushichain/crystal-ecdsa
```
2. Run `shards install`

## Usage

```crystal
require "crystal-ecdsa"

# generate a keypair
key_pair = ECCrypto.create_key_pair
private_key = key_pair[:hex_private_key]
public_key = key_pair[:hex_public_key]

# hash a text message
message = ECCrypto.sha256("this message is being signed")

# sign the message with a private key
sig = ECCrypto.sign(private_key, message)

# verify the signature with the public key and the signature
ECCrypto.verify(public_key, message, sig["r"], sig["s"])

# get the public key from a private key
public_key = ECCrypto.get_public_key_from_private(private_key)

# encrypt a message using a given receiver's public key
encrypted_message = ECCrypto.encrypt(receiver_public_key, "This is a secret message")

# decrypt a received message using known private key
decrypted_message = ECCrypto.decrypt(private_key, encrypted_message)

```

You can create a keypair which returns the public and private keys. The private key will always be of length 64 and the public key of length 130

Using the keypair you can sign a message and then verify it

## Contributing

1. Fork it (<https://github.com/sushichain/crystal-ecdsa/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Kingsley Hendrickse](https://github.com/kingsleyh) - creator and maintainer
- [John Feras](https://github.com/jferas) - contributor
