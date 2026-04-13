# noir-elgamal-grumpkin

ElGamal encryption on **Grumpkin** (Noir's native embedded curve) for [Noir](https://noir-lang.org/).

Implements exponential ElGamal with threshold decryption support, built on `std::embedded_curve_ops`. Designed for mental poker and other protocols requiring verifiable shuffle-and-decrypt over encrypted values.

Extracted from [dpinones/mental-poker](https://github.com/dpinones/mental-poker) — a mental poker protocol for Starknet using Noir ZK proofs verified on-chain via Garaga.

## Installation

Add to your `Nargo.toml`:

```toml
[dependencies]
noir_elgamal_grumpkin = { tag = "main", git = "https://github.com/critesjosh/noir-elgamal-grumpkin" }
```

**Requires** nargo 1.0.0-beta.17 or later.

## Why Grumpkin?

Grumpkin (`y² = x³ − 17`) is Noir's native embedded curve. Operations on it compile to far fewer ACIR opcodes than external curve libraries. This library uses `std::embedded_curve_ops` (`multi_scalar_mul`, `fixed_base_scalar_mul`, `EmbeddedCurvePoint` arithmetic) directly — no external dependencies.

## API

### Types

```noir
pub struct ElGamalCiphertext {
    pub c1: EmbeddedCurvePoint,
    pub c2: EmbeddedCurvePoint,
}
```

### Key Generation

```noir
pub fn priv_to_pub_key(secret_key: Field) -> EmbeddedCurvePoint
```

Derive a public key: `pk = sk * G`. Secret key must be non-zero.

### Encryption

```noir
pub fn elgamal_encrypt(
    public_key: EmbeddedCurvePoint,
    message: Field,
    randomness: Field,
) -> ElGamalCiphertext
```

Exponential ElGamal encryption. Returns `(r*G, m*G + r*PK)`.

Messages are encoded as scalar multiples of the generator — for card games, use `card_index + 1` to avoid the point at infinity.

### Re-randomization (Remask)

```noir
pub fn remask(
    ciphertext: ElGamalCiphertext,
    randomness: Field,
    public_key: EmbeddedCurvePoint,
) -> ElGamalCiphertext
```

Re-randomize a ciphertext with fresh randomness without changing the underlying plaintext. Used during shuffle rounds in mental poker.

### Threshold Decryption

```noir
pub fn partial_decrypt(
    secret_key: Field,
    c1: EmbeddedCurvePoint,
) -> EmbeddedCurvePoint
```

Compute a partial decryption token: `token = sk * C1`. In an n-party threshold scheme, each party provides their token. The plaintext point is recovered as `C2 - Σ(tokens)`.

`compute_reveal_token` is provided as a backward-compatible alias.

### Permutation Validation

```noir
pub fn assert_valid_permutation<let N: u32>(perm: [u32; N])
```

Assert that an array is a valid permutation of `[0, 1, ..., N-1]`. Useful for proving correct shuffles.

## Usage Examples

### Single-party encrypt/decrypt

```noir
use noir_elgamal_grumpkin::{priv_to_pub_key, elgamal_encrypt, partial_decrypt};
use std::embedded_curve_ops::{EmbeddedCurveScalar, fixed_base_scalar_mul};

let sk: Field = 42;
let pk = priv_to_pub_key(sk);

// Encrypt card index 0 (encoded as 0 + 1 = 1)
let encrypted = elgamal_encrypt(pk, 1, 9876);

// Decrypt
let token = partial_decrypt(sk, encrypted.c1);
let plaintext_point = encrypted.c2 - token;

// Verify: should equal 1 * G
let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(1));
assert(plaintext_point == expected);
```

### Two-party threshold decryption

```noir
use noir_elgamal_grumpkin::{priv_to_pub_key, elgamal_encrypt, partial_decrypt};

let sk1: Field = 101;
let sk2: Field = 202;
let pk1 = priv_to_pub_key(sk1);
let pk2 = priv_to_pub_key(sk2);

// Aggregate public key
let apk = pk1 + pk2;

// Encrypt with APK
let encrypted = elgamal_encrypt(apk, 7, 5555);

// Each party provides a partial decryption token
let token1 = partial_decrypt(sk1, encrypted.c1);
let token2 = partial_decrypt(sk2, encrypted.c1);

// Recover plaintext: C2 - token1 - token2
let plaintext_point = encrypted.c2 - token1 - token2;
```

### Mental poker deal simulation

```noir
use noir_elgamal_grumpkin::{priv_to_pub_key, elgamal_encrypt, remask, partial_decrypt};

let sk1: Field = 101;
let sk2: Field = 202;
let pk1 = priv_to_pub_key(sk1);
let pk2 = priv_to_pub_key(sk2);
let apk = pk1 + pk2;

// Encrypt a card with APK
let encrypted = elgamal_encrypt(apk, 1, 1000);

// Each player remasks (shuffle round)
let after_p1 = remask(encrypted, 2000, apk);
let after_p2 = remask(after_p1, 3000, apk);

// Deal to Player 1: Player 2 provides their reveal token
let token_p2 = partial_decrypt(sk2, after_p2.c1);
let token_p1 = partial_decrypt(sk1, after_p2.c1);
let decrypted = after_p2.c2 - token_p1 - token_p2;
```

## Properties

- **Additively homomorphic**: `Enc(m1, r1) + Enc(m2, r2)` decrypts to `(m1 + m2) * G`
- **Re-randomizable**: `remask` changes the ciphertext without changing the plaintext
- **Threshold-compatible**: n-of-n decryption via partial tokens, order-independent
- **Input validation**: rejects zero secret keys, zero randomness, zero messages, and points at infinity

## Scalar Domain Note

All APIs accept `Field` values for scalars. Noir's native `Field` is the BN254 scalar field (order r), while Grumpkin's scalar field is the BN254 base field (order p). The two orders differ by ~2^{-128}. The backend rejects scalars >= p at runtime. For practical use (random keys, random nonces, small card indices), inputs never fall in the gap `[p, r)`.

## License

MIT

## Origin

This library was extracted from [dpinones/mental-poker](https://github.com/dpinones/mental-poker), a mental poker protocol for Starknet built for the Starknet Re{define} hackathon. The original implementation lives in the `circuits/shared/` package of that repository.
