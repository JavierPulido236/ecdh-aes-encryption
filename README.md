# ecdh-aes-encryption

An end-to-end encrypted messaging pipeline built from scratch in Python: Elliptic Curve Diffie-Hellman (ECDH) for key exchange, then AES for the actual encryption. No external crypto libraries, everything (point addition, scalar multiplication, S-boxes, MixColumns, etc) is implemented by hand.

## What it does

1. Two parties (Alice and Bob) each generate a public/private key pair on an elliptic curve
2. They exchange public keys and independently derive the same shared secret (ECDH)
3. The shared secret is used to derive a 16-byte AES key
4. A message is encrypted using a full 10-round AES implementation
5. The message is decrypted back using the same key, to confirm the round trip works

## Running it

```bash
python Project1.py
```

Prints each step: public keys, shared keys, derived AES key, the AES state matrix through each round, the encrypted result, and the decrypted result (which matches the original message).

## Notes / limitations

This is a learning project meant to demonstrate the algorithms, not production-grade crypto:

- The elliptic curve uses a small prime (`p = 67`) for simplicity. Real ECC uses primes hundreds of bits long.
- The AES key derivation here is simplified (just stringifies and pads the shared secret's x-coordinate). A real system would use a proper KDF like HKDF.
