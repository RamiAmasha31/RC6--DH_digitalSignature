import random
from math import gcd


def generate_rsa_key_pair():
    # Generate random prime numbers p and q
    p = generate_prime_number()
    q = generate_prime_number()
    n = p * q
    # Calculate Euler's totient function phi(n)
    phi_n = (p - 1) * (q - 1)
    # Choose public exponent e
    e = select_public_exponent(phi_n)
    # Calculate modular inverse of e (private exponent d)
    d = calculate_private_exponent(e, phi_n)
    # Return public and private keys
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


def generate_blinding_factor(n):
    while True:
        r = random.randint(2, n - 1)  # Choose a random number between 2 and n-1
        if gcd(r, n) == 1:  # Check if r is relatively prime to n
            return r


def generate_prime_number():
    # Generate a random prime number within a specified range
    while True:
        prime_candidate = random.randrange(2 ** 16, 2 ** 17)
        if is_prime(prime_candidate):
            return prime_candidate


def is_prime(n, k=10):
    # Check if a number is prime using the Miller-Rabin primality test
    if n <= 1:
        return False
    # Perform Miller-Rabin test k times
    for _ in range(k):
        a = random.randrange(2, n - 1)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def select_public_exponent(phi_n):
    # Choose a public exponent e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    e = random.randint(2, phi_n - 1)
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)
    return e


def calculate_private_exponent(e, phi_n):
    # Calculate modular inverse of e (private exponent d)
    _, d, _ = extended_euclidean_algorithm(e, phi_n)
    if d < 0:
        d += phi_n
    return d


def extended_euclidean_algorithm(a, b):
    # Extended Euclidean algorithm to calculate modular inverse
    if a == 0:
        return b, 0, 1
    gcd, x, y = extended_euclidean_algorithm(b % a, a)
    return gcd, y - (b // a) * x, x


def blind_message(m, blinding_factor, n, public_key):
    blinded_message = (m * pow(blinding_factor, public_key[0], n)) % n
    return blinded_message


def sign_blinded_message(blinded_message, d, n):
    blinded_signature = pow(blinded_message, d, n)
    return blinded_signature


def compute_inverse_blinding_factor(r, n):
    inverse_blinding_factor = pow(r, -1, n)
    return inverse_blinding_factor


def unblind_signature(blinded_signature, inverse_blinding_factor, n):
    unblinded_signature = (blinded_signature * inverse_blinding_factor) % n
    return unblinded_signature


def verify_signature(unblinded_signature, e, n, message):
    verification_result = (pow(unblinded_signature, e, n) == message)
    return verification_result


def main():
    # Define the message to be signed
    message =12345666

    # Generate RSA key pair
    public_key, private_key = generate_rsa_key_pair()
    print("Original Message:", message)


    # Blinding
    blinding_factor = generate_blinding_factor(public_key[1])
    blinded_message = blind_message(message, blinding_factor, public_key[1], public_key)
    print("Blinded Message:", blinded_message)

    # Signing
    blinded_message_signature = sign_blinded_message(blinded_message, private_key[0], public_key[1])
    print("Signed Message:", blinded_message_signature)

    # Unblinding
    inverse_blinding_factor = compute_inverse_blinding_factor(blinding_factor, public_key[1])
    unblinded_message_signature = unblind_signature(blinded_message_signature, inverse_blinding_factor, public_key[1])
    print("Unblinded Message:", unblinded_message_signature)

    # Verification
    verification_result = verify_signature(unblinded_message_signature, public_key[0], public_key[1], message)
    print("Verification Result:", verification_result)
    print("The unblinded message is ",pow(unblinded_message_signature,public_key[0], public_key[1]))

if __name__ == '__main__':
    main()
