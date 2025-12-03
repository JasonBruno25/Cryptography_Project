"""
Paillier-base Secure Voting
Code
Team: Amman, Ahmad; Bruno Terceros, Jason; Ngo, Hieu; Sink, Connor
Project: Secure Voting: Cryptographic Implementations for Privacy and Verifiability

This script implements:
a simple eductional Paillier cryptosystem and shows a homomorphic tall (multiply
ciphertexts to obtain encryption of sum). 
Things to Note: uses small primes and is insecure for real elections.
"""

from __future__ import annotations
import sys
import math
import random
from typing import Tuple, List

# -------------------------
# Necessary functions for Paillier
# -------------------------

# -------------------------
# Least Common Multiple 
# -------------------------
# one of the most common functions that we might need / use is the greatest common divisor
# -------------------------
def lcm(a: int, b: int) -> int:
    return a // math.gcd(a, b) * b

# -------------------------
# Modular Inverse of a modulo m.
#     with errorException if inverse does not exist
# -------------------------
# another one that is used often is the modular inverse
# this extends the Euclidean algorithm
# useful function - returns x value in a*x = 1 (mod m)
# -------------------------
def modInv(a: int, m: int) -> int:
    g = math.gcd(a, m)
    if g != 1:
        raise ValueError(f"No inverse for {a} mod {m} (gcd={g})")
    return pow(a, -1, m)

# -------------------------
# Random Integer r in [1, n-1]
# -------------------------
# we want to make sure we can generate random numbers
# this uses random's function SystemRandom for better entropy
# -------------------------
def getRandom(n: int) -> int:
    sr = random.SystemRandom()
    while True:
        r = sr.randrange(1, n)
        if math.gcd(r, n) == 1:
            return r
        
# ---------------------------------------
# Paillier Classes
# ---------------------------------------

""""
Information Needed to complete:
Public Key: N, g
"""

# this is the public key: N and g used for the encryption
# n = p * q. while g is the generator
class PaillierPublicKey:
    def __init__(self, n: int, g: int):
        self.n = n
        self.g = g
        self.n_sq = n * n

    def __repr__(self):
        return f"PaillierPublicKey(n={self.n}, g={self.g})"

# ---------------------------------------
# ---------------------------------------  

""""
Information Needed to complete:
Private Key: p, q, lambda
"""

# this is the private key: lamdba and mu used for decryption
# λ = lcm(p−1, q−1)
# μ = (L(g^λ mod n^2))^(-1) mod n
class PaillierPrivateKey:
    def __init__(self, lambda_: int, mu: int):
        self.lambda_ = lambda_
        self.mu =  mu

    def __repr__(self):
        return f"PaillierPrivateKey(lambda={self.lambda_}, mu = {self.mu})"
    
# ---------------------------------------
# ---------------------------------------  

# ---------------------------------------
# Key Generation
# ---------------------------------------

"""
Information Needed to complete:
Public Key: N, g
Private Key: p, q, lambda
1: choose two random prime p and q, with p, q in Z_N
2: set N = p * q;
3: set lamdba = lcm(p-1, q-1),
    where lcm(*) means for greatest common divisor;
4: choose g
is an element of Z_N^2*, where the order of g is a multiple of n;
Encode:
1: plaintext d < N
2: choose a random number r < N
3: calculate ciphertext: c = g^d * r^N (mod N^2);
Decode:
1: plaintext d = F(c^lambda (mod N^2)) mu (mod N),
    where F(*) means F(mu) = mu-1/N, and mu = F(g^lambda (mod N^2))

Source: https://www.researchgate.net/figure/Paillier-homomorphic-encryption-algorithm_fig2_382970012
"""

# ---------------------------------------
# Generate a Paillier keypair
# ---------------------------------------
# Note: for demo purposes we will be using small prime values
#     these are created in the array: small_primes. For better
#     security, we could use larger prime values that fit the 
#     size of an unsigned integer value in current python version
# ---------------------------------------
def generatePaillierKey(bits: int = 512) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
    # --------------------------------------------------
    # This generates a Paillier Key
    # target bits for testing in modulus n (p and q ~ bits/2)
    # this returns a (publicKey, privateKey)
    # ---------------------------------------------------
    
    # this is for demonstration: using small prime values
    small_primes = [101, 103, 107, 109, 113, 127, 131, 137, 139, 149]
    p = random.choice(small_primes)
    q = random.choice([x for x in small_primes if x != p])

    n = p * q
    lambda_ = lcm(p-1, q-1)
    # Typical choice: g = n + 1 simplifies L(x) = (x-1)/n
    g = n + 1
    n_sq = n * n

    # mu = (L(g^lambda mod n^2))^{-1} mod n
    # we will define L(u) = (u - 1) / n
    def L(u: int) -> int:
        return (u - 1) // n

    # we compute for mu 
    x = pow(g, lambda_, n_sq)
    l_val = L(x)
    mu = modInv(l_val, n)

    # we are creating the public and private keys 
    publicKey = PaillierPublicKey(n=n, g=g)
    privateKey = PaillierPrivateKey(lambda_=lambda_, mu=mu)

    return publicKey, privateKey # we return the keys here

# ---------------------------------------
# ---------------------------------------  

# ---------------------------------------
# Encryption / Decryption
# ---------------------------------------

# ---------------------------------------
# Encryption: message m under public key
#     returns: ciphertext c in Z_{n^2}^*.
# ---------------------------------------
# Formula from info:
# c = (g^m * r^n) mod n^2
# Inputs:
# we need m for message in constraints (0 <= m < n)
# r is random integer in Z_N^* 
# ---------------------------------------
def paillier_encrypt(pub: PaillierPublicKey, m: int, r: int | None = None) -> int:
    """
    we want to encrypt message m (0 <= m < n) under pubkey. 
    r is random in Z_N^*.
    """
    # set our values
    n, g, n_sq = pub.n, pub.g, pub.n_sq

    # our constaint
    if not (0 <= m < n):
        raise ValueError("Plaintext is out of range here. It needs to be: 0 <= m < n")
    if r is None:
        r = getRandom(n)

    # ciphertext c = g^m * r^n mod n^2
    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

# ---------------------------------------
# Decryption: ciphertext c using private key
#     returns: plaintext m in [0, n-1]
# ---------------------------------------
# Formula from info:
# m = L(c^lambda mod n^2) * mu mod n
# Where L(u) = (u - 1) / n
# ---------------------------------------
def paillier_decrypt(pub: PaillierPublicKey, priv: PaillierPrivateKey, c: int) -> int:
    """Decrypt ciphertext c using private key."""
    n, n_sq = pub.n, pub.n_sq
    lambda_, mu = priv.lambda_, priv.mu

    def L(u: int) -> int:
        return (u - 1) // n

    x = pow(c, lambda_, n_sq)
    l_val = L(x)  # should be multiple of n, then /n gives plaintext modulo n
    m = (l_val * mu) % n
    return m

# ---------------------------------------
# ---------------------------------------  

# ---------------------------------------
# Homomorphic Operations:
# ---------------------------------------

# ---------------------------------------
# Homomorphic Add Singular: plaintexts corresponds to multiplication of ciphertexts
#     returns: the cipertext of the sum.
# ---------------------------------------
# The formula here is:
#     E(m1) * E(m2) mod n^2 = E(m1 + m2).
# ---------------------------------------
def homomorphic_add(pub: PaillierPublicKey, c1: int, c2: int) -> int:
    return (c1 * c2) % pub.n_sq

# ---------------------------------------
# Homomorphic Add Multiple: this is a list of ciphertexts to get encryption of the sum.
#     returns: the ciphertext of the sum of the list
# ---------------------------------------
def homomorphic_add_many(pub: PaillierPublicKey, ciphertexts: List[int]) -> int:
    if not ciphertexts:
        # Encryption of 0 is g^0 * r^n = r^n; here we build a canonical encryption of 0 using r=1
        return pow(pub.g, 0, pub.n_sq) * pow(1, pub.n, pub.n_sq) % pub.n_sq
    result = 1
    for c in ciphertexts:
        result = (result * c) % pub.n_sq
    return result


# # -------------------------
# # Demo / Simulation helpers
# # -------------------------
# def simulate_election(votes: List[int], pub: PaillierPublicKey, priv: PaillierPrivateKey, randomize: bool = True):
#     """
#     Simulate an election:
#     - votes: list of integers (e.g., 0/1 for each voter)
#     - encrypt each vote
#     - homomorphically aggregate ciphertexts
#     - decrypt final tally
#     This function prints the encrypted ballots, aggregated ciphertext, and decrypted tally.
#     """
#     print("Simulating election with votes:", votes)
#     ciphertexts = []
#     for i, v in enumerate(votes):
#         if not (0 <= v < pub.n):
#             raise ValueError(f"Vote {v} out of range for pub.n={pub.n}")
#         r = None
#         if randomize:
#             r = getRandom(pub.n)
#         c = paillier_encrypt(pub, v, r=r)
#         ciphertexts.append(c)
#         print(f" Voter {i+1}: vote={v}, ciphertext={c}")

#     aggregate = homomorphic_add_many(pub, ciphertexts)
#     print("\nAggregated ciphertext (product mod n^2):", aggregate)
#     tally = paillier_decrypt(pub, priv, aggregate)
#     print("Decrypted tally (sum of votes):", tally)
#     return ciphertexts, aggregate, tally

# # -------------------------
# # Small self-test / CLI demo
# # -------------------------
# def demo():
#     print("=== Paillier Cryptosystem Demo ===")
#     print("NOTE: This demo only uses small primes for demonstration and is not secure.\n\t To ensure security, use bigger prime values\n")

#     # Step 1: Key generation
#     pub, priv = generatePaillierKey(bits=64)
#     print(f"Public Key: n={pub.n}, g={pub.g}")
#     print(f"Private Key: lambda={priv.lambda_}, mu={priv.mu}\n")

#     # Step 2: Encrypt a sample "vote" (e.g., 1 = candidate A)
#     # Single vote demo
#     vote = 1      # this vote can change but will not throw much different results
#     c = paillier_encrypt(pub, vote)
#     print(f"Encrypting (single) vote {vote} -> ciphertext: {c}")

#     # Step 3: Decrypt to confirm correctness
#     dec = paillier_decrypt(pub, priv, c)
#     print(f"Decrypting ciphertext {c} -> plaintext: {dec}\n")

#     # Simulate an election: a few voters with 0/1 votes
#     #     this is where 0 means no and 1 means yes
#     votes = [1, 0, 1, 1, 0]  # example votes
#     # we can change this as we please
#     print("Running simulated election...")
#     simulate_election(votes, pub, priv)

# if __name__ == "__main__":
#     # Run demo by default
#     demo()