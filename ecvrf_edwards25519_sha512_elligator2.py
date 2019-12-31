import ed25519

# Python 3 implementation of ECVRF-EDWARDS25519-SHA512-Elligator2
# See https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05.pdf


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

    # 2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)

    # 3. h_string = point_to_string(H)

    # 4. Gamma = x * H

    # 5. k = ECVRF_nonce_generation(SK, h_string)

    # 6. c = ECVRF_hash_points(H, Gamma, k * B, k * H)

    # 7. s = (k + c * x) mod q

    # 8. pi_string = point_to_string(Gamma) | | int_to_string(c, n) | | int_to_string(s, qLen)

    # 9. Output pi_string
    # return pi_string
    pass


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

    # 2. If D is "INVALID", output "INVALID" and stop

    # 3.(Gamma, c, s) = D

    # 4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3

    # 5. beta_string = Hash(suite_string | | three_string | | point_to_string(cofactor * Gamma))

    # 6. Output beta_string
    # return beta_string
    pass


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

    # 3.(Gamma, c, s) = D

    # 4. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)

    # 5. U = s * B - c * public_key

    # 6. V = s * H - c * Gamma

    # 7. c’ = ECVRF_hash_points(H, Gamma, U, V)

    # 8. If c and c’ are equal, output("VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
    # return "VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
    pass


# Internal functions

# Section 5.4.1.2
def _ecvrf_hash_to_curve_elligator2_25519(suite_string, public_key, alpha_string):
    # 1. PK_string = point_to_string(public_key)

    # 2. one_string = 0x01 = int_to_string(1, 1) (a single octet with value 1)

    # 3. hash_string = Hash(suite_string | | one_string | | PK_string | | alpha_string)

    # 4. truncated_h_string = hash_string[0]...hash_string[31]

    # 5. oneTwentySeven_string = 0x7F = int_to_string(127, 1) (a single octet with value 127)

    # 6. truncated_h_string[31] = truncated_h_string[31] & oneTwentySeven_string (this step clears the high-order bit of octet 31)

    # 7. r = string_to_int(truncated_h_string)

    # 8. u = - A / (1 + 2 * (r ^ 2)) mod p (note: the inverse of (1+2 * (r ^ 2)) modulo p is guaranteed to exist)

    # 9. w = u * (u ^ 2 + A * u + 1) mod p (this step evaluates the Montgomery equation for Curve25519)

    # 10. Let e equal the Legendre symbol of w and p (see note below on how to compute e)

    # 11. If e is equal to 1 then final_u = u; else final_u = (-A - u) mod p
    #     (note: final_u is the Montgomery u-coordinate of the output; see note below on how to compute it)

    # 12. y_coordinate = (final_u - 1) / (final_u + 1) mod p
    #     (note 1: y_coordinate is the Edwards coordinate corresponding to final_u)
    #     (note 2: the inverse of (final_u + 1) modulo p is guaranteed to exist)

    # 13. h_string = int_to_string(y_coordinate, 32)

    # 14. H_prelim = string_to_point(h_string)
    #     (note: string_to_point will not return INVALID by correctness of Elligator2)

    # 15. Set H = cofactor * H_prelim

    # 16. Output H
    # return H
    pass


# Section 5.4.2.2
def _ecvrf_nonce_generation_rfc8032(secret_key, h_string):
    # 1. hashed_sk_string = Hash(secret_key)

    # 2. truncated_hashed_sk_string = hashed_sk_string[32]...hashed_sk_string[63]

    # 3. k_string = Hash(truncated_hashed_sk_string | | h_string)

    # 4. k = string_to_int(k_string) mod q

    # Output: k - an integer between 0 and q - 1
    # return k
    pass


# Section 5.4.3
def _ecvrf_hash_points(point1, point2, point_m):
    # 1. two_string = 0x02 = int_to_string(2, 1), a single octet with value 2

    # 2. Initialize str = suite_string | | two_string

    # 3. for point_j in [point1, point2, ... point_m]:
    #      str = str | | point_to_string(point_j)

    # 4. c_string = Hash(str)

    # 5. truncated_c_string = c_string[0]...c_string[n - 1]

    # 6. c = string_to_int(truncated_c_string)

    # 7. Output c
    # return c
    pass


# Section 5.4.4
def _ecvrf_decode_proof(pi_string):
    # 1. let gamma_string = pi_string[0]...p_string[ptLen - 1]

    # 2. let c_string = pi_string[ptLen]...pi_string[ptLen + n - 1]

    # 3. let s_string = pi_string[ptLen + n]...pi_string[ptLen + n + qLen - 1]

    # 4. Gamma = string_to_point(gamma_string)

    # 5. if Gamma = "INVALID" output "INVALID" and stop.

    # 6. c = string_to_int(c_string)

    # 7. s = string_to_int(s_string)

    # 8. Output Gamma, c, and s
    # return gamma, c, s
    pass
