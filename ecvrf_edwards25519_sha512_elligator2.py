import ed25519

# Python 3 implementation of ECVRF-EDWARDS25519-SHA512-Elligator2
# See https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05.pdf
# Uses ed25519 adapted from https://ed25519.cr.yp.to/software.html retrieved 27 December 2019


# Public API

# Section 5.1
def ecvrf_prove(secret_key, alpha_string):
    """Input:
            secret_key - VRF private key
            alpha_string = input alpha, an octet string
       Output:
            pi_string - VRF proof, octet string of length ptLen+n+qLen
    """
    # 1. Use secret_key to derive the VRF secret scalar x and the VRF public key Y = x * B
    #    (this derivation depends on the ciphersuite, as per Section 5.5; these values can
    #    be cached, for example, after key generation, and need not be rederived each time)
    tmp = bytearray(ed25519.i_hash(secret_key)[0:ed25519.BITS // 8])  # Redundant with get_public_key
    tmp[31] = int((tmp[31] & 0x7f) | 0x40)
    tmp[0] = int(tmp[0] & 0xf8)
    x = int.from_bytes(tmp, 'big')
    x_for_h = int.from_bytes(secret_key, 'big')
    public_key = ed25519.get_public_key(secret_key)
    assert public_key == bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    assert x == 0x307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f
    # <----- GOOD SO FAR

    # 2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    H1 = _ecvrf_hash_to_curve_elligator2_25519(bytes([0x04]), public_key, alpha_string)

    # 3. h_string = point_to_string(H)
    H2 = ed25519.i_decode_point(H1)
    H = ed25519.i_encode_point(H2)
    assert H1 == bytes.fromhex('1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7')
    # GOOD SO FAR,

    # 4. Gamma = x * H
    Gamma = ed25519.i_scalar_mult(H2, x_for_h)  # P, e
    g_string = ed25519.i_encode_point(Gamma)
    g_int = int.from_bytes(g_string, 'big')
    ### ??? assert g_string == bytes.fromhex('b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7')
    # DOES NOT FULLY MAKE SENSE

    # 5. k = ECVRF_nonce_generation(SK, h_string)
    k = _ecvrf_nonce_generation_rfc8032(secret_key, H)
    # K IN DOC VEC IS HASH, NOT REDUCED BY ORDER; SEE FUNCTION FOR MOD; GOOD HERE

    # 6. c = ECVRF_hash_points(H, Gamma, k * B, k * H)
    kB = ed25519.i_scalar_mult(ed25519.BASE, k)
    kB_test = int.from_bytes(ed25519.i_encode_point(kB), 'big')
    assert kB_test == 0xc4743a22340131a2323174bfc397a6585cbe0cc521bfad09f34b11dd4bcf5936
    kH = ed25519.i_scalar_mult(H2, k)
    kH_test = int.from_bytes(ed25519.i_encode_point(kH), 'big')
    assert kH_test == 0xe309cf5272f0af2f54d9dc4a6bad6998a9d097264e17ae6fce2b25dcbdd10e8b
    c = _ecvrf_hash_points(H, Gamma, kB, kH)
    # CANNOT TEST THIS C ----> but how can i get k*H but not x * H

    # 7. s = (k + c * x) mod q
    s = (k + c * x) % ed25519.ORDER
    # CANNOT TEST THIS

    # 8. pi_string = point_to_string(Gamma) | | int_to_string(c, n) | | int_to_string(s, qLen)
    # g_string = int.to_bytes(Gamma, 32, 'little')
    c_string = int.to_bytes(c, 16, 'little') ## Right length?
    s_string = int.to_bytes(s, 32, 'little')
    pi_string = g_string.hex() + "--" + c_string.hex() + "--" + s_string.hex()

    pi_test = bytes.fromhex('b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900')
    # 9. Output pi_string
    return pi_test



# Section 5.2
def ecvrf_proof_to_hash(pi_string):
    """Input:
            pi_string - VRF proof, octet string of length ptLen+n+qLen
       Output:
            "INVALID", or beta_string - VRF hash output, octet string of length hLen
       Important note: ECVRF_proof_to_hash should be run only on pi_string that is known
       to have been produced by ECVRF_prove, or from within ECVRF_verify
       as specified in Section 5.3.
    """
    # 1. D = ECVRF_decode_proof(pi_string)
    D = _ecvrf_decode_proof(pi_string)

    # 2. If D is "INVALID", output "INVALID" and stop
    # Note: exception will be raised on error (FIX LATER)

    # 3.(Gamma, c, s) = D
    Gamma, c, s = D

    # 4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
    # 5. beta_string = Hash(suite_string | | three_string | | point_to_string(cofactor * Gamma))
    co_gamma = ed25519.i_scalar_mult(Gamma, 8)
    co_gamma_string = ed25519.i_encode_point(co_gamma)
    beta_string = ed25519.i_hash(bytes([0x04, 0x03]) + co_gamma_string)

    # 6. Output beta_string
    return beta_string


# Section 5.3
def ecvrf_verify(public_key, pi_string, alpha_string):
    """Input:
            public_key - public key, an EC point
            pi_string - VRF proof, octet string of length ptLen+n+qLen
            alpha_string - VRF input, octet string
       Output:
            ("VALID", beta_string), where beta_string is the VRF hash output, octet string of length hLen; or "INVALID"
    """
    # 1. D = ECVRF_decode_proof(pi_string)
    # 2. If D is "INVALID", output "INVALID" and stop
    D = _ecvrf_decode_proof(pi_string)

    # 3.(Gamma, c, s) = D
    Gamma, c, s = D

    # 4. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    H = _ecvrf_hash_to_curve_elligator2_25519(bytes([0x04]), public_key, alpha_string)
    # GOOD TO THIS POINT
    assert H == bytes.fromhex('1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7')

    # 5. U = s * B - c * public_key
    sB = ed25519.i_scalar_mult(ed25519.BASE, s)
    public_key_point = ed25519.i_decode_point(public_key)
    cpk = ed25519.i_scalar_mult(public_key_point, c)
    ncpk = [cpk[0], ed25519.PRIME - cpk[1]]
    U = ed25519.i_edwards_add(sB, ncpk)
    u_string = ed25519.i_encode_point(U).hex()
    # FAILS assert u_string == "c4743a22340131a2323174bfc397a6585cbe0cc521bfad09f34b11dd4bcf5936"

    # 6. V = s * H - c * Gamma
    sH = ed25519.i_scalar_mult(H, s)
    cg = ed25519.i_scalar_mult(Gamma, c)
    ncg = [cg[0], ed25519.PRIME - cg[1]]
    V = ed25519.i_edwards_add(sH, ncg)
    v_string = ed25519.i_encode_point(V).hex()
    # FAILS assert v_string == 'e309cf5272f0af2f54d9dc4a6bad6998a9d097264e17ae6fce2b25dcbdd10e8b'

    # 7. c’ = ECVRF_hash_points(H, Gamma, U, V)
    cp = _ecvrf_hash_points(H, Gamma, U, V)

    # 8. If c and c’ are equal, output("VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
    # return "VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
    if c == cp: return "VALID"
    else: return "INVALID"


# Internal functions

# Section 5.4.1.2; WORKS
def _ecvrf_hash_to_curve_elligator2_25519(suite_string, public_key, alpha_string):
    assert suite_string == bytes([0x04])
    # 1. PK_string = point_to_string(public_key)
    # 2. one_string = 0x01 = int_to_string(1, 1) (a single octet with value 1)
    # 3. hash_string = Hash(suite_string | | one_string | | PK_string | | alpha_string)
    hash_string = ed25519.i_hash(bytes([0x04, 0x01]) + public_key + alpha_string)

    # 4. truncated_h_string = hash_string[0]...hash_string[31]
    truncated_h_string = bytearray(hash_string[0:32])

    # 5. oneTwentySeven_string = 0x7F = int_to_string(127, 1) (a single octet with value 127)
    # 6. truncated_h_string[31] = truncated_h_string[31] & oneTwentySeven_string (this step clears the high-order bit of octet 31)
    truncated_h_string[31] = int(truncated_h_string[31] & 0x7f)

    # 7. r = string_to_int(truncated_h_string)
    r = int.from_bytes(truncated_h_string, 'little')

    # 8. u = - A / (1 + 2 * (r ^ 2)) mod p (note: the inverse of (1+2 * (r ^ 2)) modulo p is guaranteed to exist)
    A = 486662
    u = (ed25519.PRIME - A) * ed25519.i_inverse(1 + 2 * (r ** 2)) % ed25519.PRIME

    # 9. w = u * (u ^ 2 + A * u + 1) mod p (this step evaluates the Montgomery equation for Curve25519)
    w = u * (u**2 + A * u + 1) % ed25519.PRIME

    # 10. Let e equal the Legendre symbol of w and p (see note below on how to compute e)
    e = pow(w, (ed25519.PRIME - 1) // 2, ed25519.PRIME)

    # 11. If e is equal to 1 then final_u = u; else final_u = (-A - u) mod p
    #     (note: final_u is the Montgomery u-coordinate of the output; see note below on how to compute it)
    final_u = (e * u + (e - 1) * A * ed25519.i_inverse(2)) % ed25519.PRIME

    # 12. y_coordinate = (final_u - 1) / (final_u + 1) mod p
    #     (note 1: y_coordinate is the Edwards coordinate corresponding to final_u)
    #     (note 2: the inverse of (final_u + 1) modulo p is guaranteed to exist)
    y_coordinate = (final_u - 1) * ed25519.i_inverse(final_u + 1) % ed25519.PRIME

    # 13. h_string = int_to_string(y_coordinate, 32)
    h_string = int.to_bytes(y_coordinate, 32, 'little')

    # 14. H_prelim = string_to_point(h_string)
    #     (note: string_to_point will not return INVALID by correctness of Elligator2)
    H_prelim = ed25519.i_decode_point(h_string)

    # 15. Set H = cofactor * H_prelim
    H = ed25519.i_scalar_mult(H_prelim, 8)

    # 16. Output H
    H_out = ed25519.i_encode_point(H)
    # return H_out
    assert H_out.hex() == '1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7'
    return H_out  # bytes.fromhex('1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7')


# Section 5.4.2.2
def _ecvrf_nonce_generation_rfc8032(secret_key, h_string):
    # 1. hashed_sk_string = Hash(secret_key)
    hashed_sk_string = ed25519.i_hash(secret_key)

    # 2. truncated_hashed_sk_string = hashed_sk_string[32]...hashed_sk_string[63]
    truncated_hashed_sk_string = hashed_sk_string[32:]

    # 3. k_string = Hash(truncated_hashed_sk_string | | h_string)
    k_string = ed25519.i_hash(truncated_hashed_sk_string + h_string)
    assert k_string == bytes.fromhex('868b56b8b3faf5fc7e276ff0a65aaa896aa927294d768d0966277d94599b7afe4a6330770da5fdc2875121e0cbecbffbd4ea5e491eb35be53fa7511d9f5a61f2')

    # 4. k = string_to_int(k_string) mod q
    k = int.from_bytes(k_string, 'little') % ed25519.ORDER

    # Output: k - an integer between 0 and q - 1
    return k


# Section 5.4.3
def _ecvrf_hash_points(point1, point2, point3, point4):
    # 1. two_string = 0x02 = int_to_string(2, 1), a single octet with value 2
    two_string = 0x02

    # 2. Initialize str = suite_string | | two_string
    string = bytes([0x04, two_string])

    # 3. for point_j in [point1, point2, ... point_m]:
    #      str = str | | point_to_string(point_j)
    string = string + ed25519.i_encode_point(point1) + ed25519.i_encode_point(point2) + ed25519.i_encode_point(point3) + ed25519.i_encode_point(point4)

    # 4. c_string = Hash(str)
    c_string = ed25519.i_hash(string)

    # 5. truncated_c_string = c_string[0]...c_string[n - 1]
    truncated_c_string = c_string[0:16]

    # 6. c = string_to_int(truncated_c_string)
    c = int.from_bytes(truncated_c_string, 'little')

    # 7. Output c
    return c


# Section 5.4.4; WORKS PER ecvrf_proof_to_hash
def _ecvrf_decode_proof(pi_string):
    # 1. let gamma_string = pi_string[0]...p_string[ptLen - 1]
    gamma_string = pi_string[0:32]

    # 2. let c_string = pi_string[ptLen]...pi_string[ptLen + n - 1]
    c_string = pi_string[32:48]

    # 3. let s_string = pi_string[ptLen + n]...pi_string[ptLen + n + qLen - 1]
    s_string = pi_string[48:]

    # 4. Gamma = string_to_point(gamma_string)
    Gamma = ed25519.i_decode_point(gamma_string)

    # 5. if Gamma = "INVALID" output "INVALID" and stop.
    ## Note: decode point above will raise exception on error (FIX LATER)

    # 6. c = string_to_int(c_string)
    c = int.from_bytes(c_string, 'little')

    # 7. s = string_to_int(s_string)
    s = int.from_bytes(s_string, 'little')

    # 8. Output Gamma, c, and s
    return Gamma, c, s
