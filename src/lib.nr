/// ElGamal encryption on Grumpkin (Noir's native embedded curve) for mental poker.
///
/// # Scalar domain
/// All public APIs accept `Field` values for scalars (secret keys, randomness, messages)
/// and convert them via `EmbeddedCurveScalar::from_field`. Noir's native `Field` is the
/// BN254 scalar field (order r), while Grumpkin's scalar field is the BN254 base field
/// (order p). The two orders differ by ~2^{-128} in relative terms. The backend rejects
/// scalars >= p at runtime rather than silently reducing them. For practical use -- random
/// secret keys, random nonces, and small card indices (1-52) -- inputs never fall in the
/// gap [p, r), so this rejection cannot trigger.
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul, fixed_base_scalar_mul,
};

/// An ElGamal ciphertext: two curve points (C1, C2).
/// C1 = r * G, C2 = m * G + r * PK
pub struct ElGamalCiphertext {
    pub c1: EmbeddedCurvePoint,
    pub c2: EmbeddedCurvePoint,
}

// ============================================================
// Key operations
// ============================================================

/// Derive public key from secret key: pk = sk * G
pub fn priv_to_pub_key(secret_key: Field) -> EmbeddedCurvePoint {
    assert(secret_key != 0, "Secret key must be non-zero");
    let sk = EmbeddedCurveScalar::from_field(secret_key);
    fixed_base_scalar_mul(sk)
}

// ============================================================
// ElGamal encryption (exponential form)
// ============================================================

/// Encrypt a message using exponential ElGamal.
/// For small message spaces (e.g. card indices), encode as (index + 1) to avoid
/// the point at infinity. Returns (r*G, message*G + r*PK).
pub fn elgamal_encrypt(
    public_key: EmbeddedCurvePoint,
    message: Field,
    randomness: Field,
) -> ElGamalCiphertext {
    assert(!public_key.is_infinite, "Public key must not be the point at infinity");
    assert(randomness != 0, "Randomness must be non-zero");
    assert(message != 0, "Message must be non-zero (use index + 1 encoding)");
    let r = EmbeddedCurveScalar::from_field(randomness);
    let m = EmbeddedCurveScalar::from_field(message);

    // C1 = r * G
    let c1 = fixed_base_scalar_mul(r);

    // C2 = m * G + r * PK  (single multi-scalar-mul for efficiency)
    let c2 = multi_scalar_mul(
        [EmbeddedCurvePoint::generator(), public_key],
        [m, r],
    );

    ElGamalCiphertext { c1, c2 }
}

// ============================================================
// Remask: re-randomize a ciphertext
// ============================================================

/// Re-randomize a ciphertext with fresh randomness.
/// new_C1 = C1 + r * G
/// new_C2 = C2 + r * PK
pub fn remask(
    ciphertext: ElGamalCiphertext,
    randomness: Field,
    public_key: EmbeddedCurvePoint,
) -> ElGamalCiphertext {
    assert(!ciphertext.c1.is_infinite, "Ciphertext C1 must not be the point at infinity");
    assert(!ciphertext.c2.is_infinite, "Ciphertext C2 must not be the point at infinity");
    assert(!public_key.is_infinite, "Public key must not be the point at infinity");
    assert(randomness != 0, "Randomness must be non-zero");
    let r = EmbeddedCurveScalar::from_field(randomness);
    let one = EmbeddedCurveScalar::from_field(1);

    // new_C1 = 1 * C1 + r * G  (single MSM)
    let new_c1 = multi_scalar_mul(
        [ciphertext.c1, EmbeddedCurvePoint::generator()],
        [one, r],
    );

    // new_C2 = 1 * C2 + r * PK  (single MSM)
    let new_c2 = multi_scalar_mul(
        [ciphertext.c2, public_key],
        [one, r],
    );

    ElGamalCiphertext { c1: new_c1, c2: new_c2 }
}

// ============================================================
// Threshold decryption: partial decrypt (reveal token)
// ============================================================

/// Compute a partial decryption token: token = sk * C1.
/// In a threshold scheme, each party provides their token.
/// The plaintext point is recovered as C2 - sum(tokens).
pub fn partial_decrypt(
    secret_key: Field,
    c1: EmbeddedCurvePoint,
) -> EmbeddedCurvePoint {
    assert(secret_key != 0, "Secret key must be non-zero");
    assert(!c1.is_infinite, "C1 must not be the point at infinity");
    let sk = EmbeddedCurveScalar::from_field(secret_key);
    multi_scalar_mul([c1], [sk])
}

/// Backward-compatible alias for `partial_decrypt`.
pub fn compute_reveal_token(
    secret_key: Field,
    c1: EmbeddedCurvePoint,
) -> EmbeddedCurvePoint {
    partial_decrypt(secret_key, c1)
}

// ============================================================
// Permutation validation
// ============================================================

/// Assert that `perm` is a valid permutation of [0, 1, ..., N-1].
/// Uses sort-and-compare approach.
pub fn assert_valid_permutation<let N: u32>(perm: [u32; N]) {
    let sorted = perm.sort();
    for i in 0..N {
        assert(sorted[i] == i as u32, "Invalid permutation");
    }
}

// ============================================================
// Tests
// ============================================================

#[test]
fn test_key_generation() {
    let sk: Field = 42;
    let pk = priv_to_pub_key(sk);
    // pk should not be the point at infinity
    assert(!pk.is_infinite);
    // Same secret key should give same public key
    let pk2 = priv_to_pub_key(sk);
    assert(pk.x == pk2.x);
    assert(pk.y == pk2.y);
}

#[test]
fn test_different_keys_different_pubkeys() {
    let pk1 = priv_to_pub_key(1);
    let pk2 = priv_to_pub_key(2);
    assert(pk1.x != pk2.x);
}

#[test]
fn test_elgamal_encrypt_decrypt() {
    let sk: Field = 7;
    let pk = priv_to_pub_key(sk);

    let message: Field = 5;
    let randomness: Field = 13;

    let encrypted = elgamal_encrypt(pk, message, randomness);

    // Decrypt: plaintext_point = C2 - sk * C1
    let sk_c1 = partial_decrypt(sk, encrypted.c1);
    let decrypted = encrypted.c2 - sk_c1;

    // The decrypted point should be message * G
    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

#[test]
fn test_remask_preserves_plaintext() {
    // Encrypt, then remask with fresh randomness.
    // Decrypting the remasked ciphertext should yield the same plaintext.
    let sk: Field = 11;
    let pk = priv_to_pub_key(sk);

    let message: Field = 3;
    let r1: Field = 17;
    let r2: Field = 23;

    let encrypted = elgamal_encrypt(pk, message, r1);
    let remasked = remask(encrypted, r2, pk);

    // Decrypt remasked: C2' - sk * C1'
    let sk_c1 = partial_decrypt(sk, remasked.c1);
    let decrypted = remasked.c2 - sk_c1;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

#[test]
fn test_aggregate_key_decrypt() {
    // Two parties: each has a secret key. The aggregate public key is pk1 + pk2.
    // Encrypt with APK, then each party provides a partial decryption token.
    let sk1: Field = 5;
    let sk2: Field = 9;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let apk = pk1 + pk2;

    let message: Field = 7;
    let randomness: Field = 19;

    let encrypted = elgamal_encrypt(apk, message, randomness);

    // Each party computes their partial decryption token
    let token1 = partial_decrypt(sk1, encrypted.c1);
    let token2 = partial_decrypt(sk2, encrypted.c1);

    // Decrypt: C2 - token1 - token2
    let decrypted = encrypted.c2 - token1 - token2;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

#[test]
fn test_key_from_one() {
    // Edge case: smallest valid secret key
    let pk = priv_to_pub_key(1);
    // pk = 1 * G = G (the generator itself)
    let g = EmbeddedCurvePoint::generator();
    assert(pk.x == g.x);
    assert(pk.y == g.y);
}

#[test]
fn test_encrypt_same_message_different_randomness() {
    // Encrypting the same message with different randomness must produce different ciphertexts
    let pk = priv_to_pub_key(5);
    let enc1 = elgamal_encrypt(pk, 10, 100);
    let enc2 = elgamal_encrypt(pk, 10, 200);
    // C1 must differ (different r * G)
    assert(enc1.c1.x != enc2.c1.x);
    // C2 must also differ
    assert(enc2.c2.x != enc1.c2.x);
}

#[test]
fn test_three_party_aggregate_decrypt() {
    // Three parties: encrypt with APK = pk1 + pk2 + pk3, decrypt with all three tokens
    let sk1: Field = 11;
    let sk2: Field = 22;
    let sk3: Field = 33;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let pk3 = priv_to_pub_key(sk3);
    let apk = pk1 + pk2 + pk3;

    let message: Field = 42;
    let encrypted = elgamal_encrypt(apk, message, 77);

    let token1 = partial_decrypt(sk1, encrypted.c1);
    let token2 = partial_decrypt(sk2, encrypted.c1);
    let token3 = partial_decrypt(sk3, encrypted.c1);

    let decrypted = encrypted.c2 - token1 - token2 - token3;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

#[test]
fn test_remask_twice_still_decrypts() {
    // Remask twice (simulating 2 shuffle rounds), should still decrypt correctly
    let sk: Field = 13;
    let pk = priv_to_pub_key(sk);

    let message: Field = 7;
    let encrypted = elgamal_encrypt(pk, message, 50);
    let remasked1 = remask(encrypted, 60, pk);
    let remasked2 = remask(remasked1, 70, pk);

    let token = partial_decrypt(sk, remasked2.c1);
    let decrypted = remasked2.c2 - token;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

#[test]
fn test_partial_decrypt_different_ciphertexts() {
    // Partial decryption tokens for different ciphertexts must be different
    let sk: Field = 5;
    let pk = priv_to_pub_key(sk);

    let enc_a = elgamal_encrypt(pk, 1, 100);
    let enc_b = elgamal_encrypt(pk, 2, 200);

    let token_a = partial_decrypt(sk, enc_a.c1);
    let token_b = partial_decrypt(sk, enc_b.c1);

    // Different C1 means different token
    assert(token_a.x != token_b.x);
}

#[test]
fn test_valid_permutation() {
    assert_valid_permutation([2, 0, 3, 1]);
    assert_valid_permutation([0, 1, 2, 3]);
    assert_valid_permutation([3, 2, 1, 0]);
}

#[test(should_fail)]
fn test_invalid_permutation() {
    assert_valid_permutation([0, 0, 2, 3]); // duplicate 0, missing 1
}

#[test]
fn test_identity_permutation() {
    assert_valid_permutation([0, 1, 2, 3, 4]);
}

#[test(should_fail)]
fn test_permutation_out_of_range() {
    assert_valid_permutation([0, 1, 2, 99]); // 99 is out of range for N=4
}

#[test(should_fail)]
fn test_permutation_all_zeros() {
    assert_valid_permutation([0, 0, 0, 0]);
}

// ============================================================
// Additional tests
// ============================================================

// --- Key generation ---

#[test]
fn test_key_from_generator_scalar() {
    // sk = 2 should give 2*G
    let pk = priv_to_pub_key(2);
    let g = EmbeddedCurvePoint::generator();
    let expected = g + g;
    assert(pk.x == expected.x);
    assert(pk.y == expected.y);
}

#[test]
fn test_key_large_secret() {
    // A larger secret key should still produce a valid point
    let sk: Field = 123456789012345678;
    let pk = priv_to_pub_key(sk);
    assert(!pk.is_infinite);
}

#[test]
fn test_public_key_on_curve() {
    // Verify pk satisfies Grumpkin: y^2 = x^3 - 17
    let pk = priv_to_pub_key(42);
    let y_sq = pk.y * pk.y;
    let x_cu = pk.x * pk.x * pk.x;
    assert(y_sq == x_cu - 17);
}

// --- Encrypt / decrypt ---

#[test]
fn test_encrypt_message_one_gives_generator() {
    // Encrypting message=1 and decrypting should yield G
    let sk: Field = 7;
    let pk = priv_to_pub_key(sk);
    let encrypted = elgamal_encrypt(pk, 1, 99);
    let token = partial_decrypt(sk, encrypted.c1);
    let decrypted = encrypted.c2 - token;
    let g = EmbeddedCurvePoint::generator();
    assert(decrypted.x == g.x);
    assert(decrypted.y == g.y);
}

#[test]
fn test_encrypt_different_keys_same_randomness() {
    // Same message and randomness but different keys must produce different C2
    let pk1 = priv_to_pub_key(3);
    let pk2 = priv_to_pub_key(7);
    let enc1 = elgamal_encrypt(pk1, 5, 42);
    let enc2 = elgamal_encrypt(pk2, 5, 42);
    // C1 = r*G is the same since randomness is the same
    assert(enc1.c1.x == enc2.c1.x);
    assert(enc1.c1.y == enc2.c1.y);
    // C2 must differ because PK differs
    assert(enc1.c2.x != enc2.c2.x);
}

#[test]
fn test_encrypt_different_messages_same_randomness() {
    // Same key and randomness but different messages must produce different C2
    let pk = priv_to_pub_key(5);
    let enc1 = elgamal_encrypt(pk, 1, 42);
    let enc2 = elgamal_encrypt(pk, 2, 42);
    // C1 = r*G should be the same
    assert(enc1.c1.x == enc2.c1.x);
    // C2 must differ since message differs
    assert(enc1.c2.x != enc2.c2.x);
}

#[test]
fn test_decrypt_wrong_key_gives_wrong_result() {
    // Decrypting with the wrong secret key should NOT yield the original message point
    let sk_correct: Field = 7;
    let sk_wrong: Field = 8;
    let pk = priv_to_pub_key(sk_correct);

    let message: Field = 5;
    let encrypted = elgamal_encrypt(pk, message, 13);

    // Decrypt with wrong key
    let wrong_token = partial_decrypt(sk_wrong, encrypted.c1);
    let decrypted_wrong = encrypted.c2 - wrong_token;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    // Should NOT match
    assert(decrypted_wrong.x != expected.x);
}

// --- Card encoding roundtrip ---

#[test]
fn test_card_encoding_roundtrip_several_values() {
    // The protocol encodes card i as (i+1)*G to avoid point at infinity.
    // Verify encrypt-decrypt roundtrip for several card indices.
    let sk: Field = 17;
    let pk = priv_to_pub_key(sk);

    // Test card indices 0, 1, 10, 25, 51 (first, second, mid, late, last of a 52-card deck)
    let card_indices: [Field; 5] = [1, 2, 11, 26, 52]; // already encoded as index+1
    let randomnesses: [Field; 5] = [101, 202, 303, 404, 505];

    for i in 0..5 {
        let encrypted = elgamal_encrypt(pk, card_indices[i], randomnesses[i]);
        let token = partial_decrypt(sk, encrypted.c1);
        let decrypted = encrypted.c2 - token;
        let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(card_indices[i]));
        assert(decrypted.x == expected.x);
        assert(decrypted.y == expected.y);
    }
}

// --- Homomorphic addition ---

#[test]
fn test_additive_homomorphism() {
    // ElGamal in exponential form is additively homomorphic:
    // Enc(m1, r1) + Enc(m2, r2) decrypts to (m1 + m2) * G
    let sk: Field = 11;
    let pk = priv_to_pub_key(sk);

    let m1: Field = 3;
    let m2: Field = 5;
    let enc1 = elgamal_encrypt(pk, m1, 100);
    let enc2 = elgamal_encrypt(pk, m2, 200);

    // Add ciphertexts component-wise
    let sum_c1 = enc1.c1 + enc2.c1;
    let sum_c2 = enc1.c2 + enc2.c2;

    // Decrypt the sum
    let token = partial_decrypt(sk, sum_c1);
    let decrypted = sum_c2 - token;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(m1 + m2));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

// --- Threshold decryption ---

#[test]
fn test_partial_decrypt_token_order_independent() {
    // Subtracting tokens in different order should give the same result.
    let sk1: Field = 5;
    let sk2: Field = 9;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let apk = pk1 + pk2;

    let message: Field = 7;
    let encrypted = elgamal_encrypt(apk, message, 19);

    let token1 = partial_decrypt(sk1, encrypted.c1);
    let token2 = partial_decrypt(sk2, encrypted.c1);

    // Order 1: subtract token1 first, then token2
    let decrypted_a = encrypted.c2 - token1 - token2;
    // Order 2: subtract token2 first, then token1
    let decrypted_b = encrypted.c2 - token2 - token1;

    assert(decrypted_a.x == decrypted_b.x);
    assert(decrypted_a.y == decrypted_b.y);

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted_a.x == expected.x);
    assert(decrypted_a.y == expected.y);
}

#[test]
fn test_missing_token_fails_decryption() {
    // With 2-party APK, providing only 1 token should NOT decrypt correctly
    let sk1: Field = 5;
    let sk2: Field = 9;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let apk = pk1 + pk2;

    let message: Field = 7;
    let encrypted = elgamal_encrypt(apk, message, 19);

    // Only provide token from party 1
    let token1 = partial_decrypt(sk1, encrypted.c1);
    let partial_result = encrypted.c2 - token1;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    // Should NOT match - missing party 2's contribution
    assert(partial_result.x != expected.x);
}

#[test]
fn test_four_party_aggregate_decrypt() {
    let sk1: Field = 11;
    let sk2: Field = 22;
    let sk3: Field = 33;
    let sk4: Field = 44;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let pk3 = priv_to_pub_key(sk3);
    let pk4 = priv_to_pub_key(sk4);
    let apk = pk1 + pk2 + pk3 + pk4;

    let message: Field = 10;
    let encrypted = elgamal_encrypt(apk, message, 55);

    let token1 = partial_decrypt(sk1, encrypted.c1);
    let token2 = partial_decrypt(sk2, encrypted.c1);
    let token3 = partial_decrypt(sk3, encrypted.c1);
    let token4 = partial_decrypt(sk4, encrypted.c1);

    let decrypted = encrypted.c2 - token1 - token2 - token3 - token4;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

// --- Remask ---

#[test]
fn test_remask_changes_ciphertext() {
    // Remasking should actually change the ciphertext points
    let sk: Field = 11;
    let pk = priv_to_pub_key(sk);
    let encrypted = elgamal_encrypt(pk, 5, 50);
    let remasked = remask(encrypted, 60, pk);

    // C1 and C2 should be different from the original
    assert(encrypted.c1.x != remasked.c1.x);
    assert(encrypted.c2.x != remasked.c2.x);
}

#[test]
fn test_remask_different_randomness_gives_different_ciphertexts() {
    let sk: Field = 11;
    let pk = priv_to_pub_key(sk);
    let encrypted = elgamal_encrypt(pk, 5, 50);

    let remasked1 = remask(encrypted, 60, pk);
    let remasked2 = remask(encrypted, 70, pk);

    // Two remasks with different randomness should produce different ciphertexts
    assert(remasked1.c1.x != remasked2.c1.x);
    assert(remasked1.c2.x != remasked2.c2.x);

    // But both should still decrypt to the same plaintext
    let token1 = partial_decrypt(sk, remasked1.c1);
    let dec1 = remasked1.c2 - token1;
    let token2 = partial_decrypt(sk, remasked2.c1);
    let dec2 = remasked2.c2 - token2;

    assert(dec1.x == dec2.x);
    assert(dec1.y == dec2.y);
}

#[test]
fn test_remask_with_aggregate_key_and_threshold_decrypt() {
    // Encrypt with APK, remask with APK, then all parties provide tokens
    let sk1: Field = 5;
    let sk2: Field = 9;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let apk = pk1 + pk2;

    let message: Field = 7;
    let encrypted = elgamal_encrypt(apk, message, 19);
    let remasked = remask(encrypted, 31, apk);

    let token1 = partial_decrypt(sk1, remasked.c1);
    let token2 = partial_decrypt(sk2, remasked.c1);
    let decrypted = remasked.c2 - token1 - token2;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

#[test]
fn test_three_remasks_with_aggregate_key() {
    // Simulates 3-player shuffle: each remasks with APK
    let sk1: Field = 11;
    let sk2: Field = 22;
    let sk3: Field = 33;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let pk3 = priv_to_pub_key(sk3);
    let apk = pk1 + pk2 + pk3;

    let message: Field = 42;
    let encrypted = elgamal_encrypt(apk, message, 100);

    // Each player remasks (simulating their shuffle round)
    let after_p1 = remask(encrypted, 111, apk);
    let after_p2 = remask(after_p1, 222, apk);
    let after_p3 = remask(after_p2, 333, apk);

    // All three parties provide tokens to decrypt
    let token1 = partial_decrypt(sk1, after_p3.c1);
    let token2 = partial_decrypt(sk2, after_p3.c1);
    let token3 = partial_decrypt(sk3, after_p3.c1);
    let decrypted = after_p3.c2 - token1 - token2 - token3;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(message));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

// --- Ciphertext structure ---

#[test]
fn test_c1_is_r_times_generator() {
    // Verify C1 = r * G directly
    let pk = priv_to_pub_key(5);
    let r: Field = 42;
    let encrypted = elgamal_encrypt(pk, 10, r);

    let expected_c1 = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(r));
    assert(encrypted.c1.x == expected_c1.x);
    assert(encrypted.c1.y == expected_c1.y);
}

#[test]
fn test_c2_structure() {
    // Verify C2 = m*G + r*PK
    let sk: Field = 5;
    let pk = priv_to_pub_key(sk);
    let m: Field = 10;
    let r: Field = 42;
    let encrypted = elgamal_encrypt(pk, m, r);

    let m_g = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(m));
    let r_pk = multi_scalar_mul([pk], [EmbeddedCurveScalar::from_field(r)]);
    let expected_c2 = m_g + r_pk;

    assert(encrypted.c2.x == expected_c2.x);
    assert(encrypted.c2.y == expected_c2.y);
}

// --- Reveal token / partial_decrypt alias ---

#[test]
fn test_compute_reveal_token_matches_partial_decrypt() {
    let sk: Field = 7;
    let pk = priv_to_pub_key(sk);
    let encrypted = elgamal_encrypt(pk, 5, 13);

    let token_a = partial_decrypt(sk, encrypted.c1);
    let token_b = compute_reveal_token(sk, encrypted.c1);

    assert(token_a.x == token_b.x);
    assert(token_a.y == token_b.y);
}

#[test]
fn test_reveal_token_not_infinite() {
    // A reveal token should be a valid non-infinite point
    let sk: Field = 7;
    let pk = priv_to_pub_key(sk);
    let encrypted = elgamal_encrypt(pk, 5, 13);
    let token = partial_decrypt(sk, encrypted.c1);
    assert(!token.is_infinite);
}

// --- Permutation edge cases ---

#[test]
fn test_permutation_single_element() {
    assert_valid_permutation([0]);
}

#[test]
fn test_permutation_two_elements_swap() {
    assert_valid_permutation([1, 0]);
}

#[test]
fn test_permutation_two_elements_identity() {
    assert_valid_permutation([0, 1]);
}

#[test(should_fail)]
fn test_permutation_duplicate_last() {
    assert_valid_permutation([0, 1, 2, 2]); // duplicate 2, missing 3
}

#[test(should_fail)]
fn test_permutation_missing_zero() {
    assert_valid_permutation([1, 2, 3, 4]); // missing 0, has 4 which is out of range
}

// --- Full mental poker deal simulation ---

#[test]
fn test_full_deal_simulation_two_players() {
    // Simulates dealing one card in a 2-player mental poker game:
    // 1. Both players derive keys
    // 2. Compute aggregate public key
    // 3. Encrypt a card with APK
    // 4. Player 1 remasks (shuffle round 1)
    // 5. Player 2 remasks (shuffle round 2)
    // 6. To deal card to Player 1: Player 2 provides reveal token
    // 7. Player 1 decrypts using their sk and Player 2's token

    let sk1: Field = 101;
    let sk2: Field = 202;
    let pk1 = priv_to_pub_key(sk1);
    let pk2 = priv_to_pub_key(sk2);
    let apk = pk1 + pk2;

    // Card "Ace of Spades" encoded as (0 + 1) = 1
    let card_value: Field = 1;
    let encrypted = elgamal_encrypt(apk, card_value, 1000);

    // Player 1 shuffles (remasks)
    let after_p1 = remask(encrypted, 2000, apk);
    // Player 2 shuffles (remasks)
    let after_p2 = remask(after_p1, 3000, apk);

    // Deal to Player 1: Player 2 provides their reveal token
    let token_p2 = partial_decrypt(sk2, after_p2.c1);

    // Player 1 decrypts: C2 - sk1*C1 - token_p2
    let token_p1 = partial_decrypt(sk1, after_p2.c1);
    let decrypted = after_p2.c2 - token_p1 - token_p2;

    let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(card_value));
    assert(decrypted.x == expected.x);
    assert(decrypted.y == expected.y);
}

#[test]
fn test_distinct_card_encodings() {
    // All 52 card values (encoded as index+1) should map to distinct points
    // Test a subset to keep circuit size manageable
    let vals: [Field; 10] = [1, 2, 3, 4, 5, 10, 20, 30, 40, 52];
    let mut points_x: [Field; 10] = [0; 10];

    for i in 0..10 {
        let pt = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(vals[i]));
        points_x[i] = pt.x;
        assert(!pt.is_infinite);
    }

    // All x-coordinates should be distinct
    for i in 0..10 {
        for j in (i + 1)..10 {
            assert(points_x[i] != points_x[j]);
        }
    }
}

#[test]
fn test_encrypt_decrypt_all_card_range() {
    // Encrypt and decrypt card values 1..8 (subset to keep test fast)
    let sk: Field = 77;
    let pk = priv_to_pub_key(sk);

    for i in 0..8 {
        let card: Field = (i + 1) as Field;
        let r: Field = (i as Field + 1) * 1000;
        let encrypted = elgamal_encrypt(pk, card, r);
        let token = partial_decrypt(sk, encrypted.c1);
        let decrypted = encrypted.c2 - token;
        let expected = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(card));
        assert(decrypted.x == expected.x);
        assert(decrypted.y == expected.y);
    }
}

// ============================================================
// Degenerate input rejection tests
// ============================================================

#[test(should_fail_with = "Secret key must be non-zero")]
fn test_priv_to_pub_key_rejects_zero() {
    let _ = priv_to_pub_key(0);
}

#[test(should_fail_with = "Randomness must be non-zero")]
fn test_encrypt_rejects_zero_randomness() {
    let pk = priv_to_pub_key(1);
    let _ = elgamal_encrypt(pk, 1, 0);
}

#[test(should_fail_with = "Message must be non-zero")]
fn test_encrypt_rejects_zero_message() {
    let pk = priv_to_pub_key(1);
    let _ = elgamal_encrypt(pk, 0, 42);
}

#[test(should_fail_with = "Randomness must be non-zero")]
fn test_remask_rejects_zero_randomness() {
    let pk = priv_to_pub_key(1);
    let ct = elgamal_encrypt(pk, 1, 42);
    let _ = remask(ct, 0, pk);
}

#[test(should_fail_with = "Secret key must be non-zero")]
fn test_partial_decrypt_rejects_zero_secret_key() {
    let pk = priv_to_pub_key(1);
    let ct = elgamal_encrypt(pk, 1, 42);
    let _ = partial_decrypt(0, ct.c1);
}

// --- Point-at-infinity rejection tests ---

#[test(should_fail_with = "Public key must not be the point at infinity")]
fn test_encrypt_rejects_infinite_public_key() {
    let infinity = EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true };
    let _ = elgamal_encrypt(infinity, 1, 42);
}

#[test(should_fail_with = "Public key must not be the point at infinity")]
fn test_remask_rejects_infinite_public_key() {
    let pk = priv_to_pub_key(1);
    let ct = elgamal_encrypt(pk, 1, 42);
    let infinity = EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true };
    let _ = remask(ct, 99, infinity);
}

#[test(should_fail_with = "Ciphertext C1 must not be the point at infinity")]
fn test_remask_rejects_infinite_c1() {
    let pk = priv_to_pub_key(1);
    let infinity = EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true };
    let ct = ElGamalCiphertext { c1: infinity, c2: pk };
    let _ = remask(ct, 99, pk);
}

#[test(should_fail_with = "Ciphertext C2 must not be the point at infinity")]
fn test_remask_rejects_infinite_c2() {
    let pk = priv_to_pub_key(1);
    let infinity = EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true };
    let ct = ElGamalCiphertext { c1: pk, c2: infinity };
    let _ = remask(ct, 99, pk);
}

#[test(should_fail_with = "C1 must not be the point at infinity")]
fn test_partial_decrypt_rejects_infinite_c1() {
    let infinity = EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true };
    let _ = partial_decrypt(1, infinity);
}
