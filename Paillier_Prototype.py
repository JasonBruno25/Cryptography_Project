"""
Paillier-based secure voting prototype
Draft Code
Team: Amman, Ahmad; Bruno Terceros, Jason; Ngo, Hieu; Sink, Connor
Project: Secure Voting: Cryptographic Implementations for Privacy and Verifiability

This script provides:
This draft implements a simple prototype of the Paillier Cryptosystem,
a partially homomorphic public-key encryption scheme that supports
addition on encrypted values. For secure electronic voting, this 
additive homomorphism allows encrypted votes to be tallied without 
decrypting individual ballots, ensuring voter privacy while maintaining verifiability.
---------------- TO DO LATER --------------------------
Later we will try to simulate a small election with multiple encrypted votes.
We will also add homomorphic tallying demonstrations. Zero-Knowledge Pros for
verifiability. And finally include real world constrints such as ballot limits,
voter validation
"""

from __future__ import annotations
import sys
import math
import random
from typing import Tuple

# one of the most common functions that we might need / use is the greatest common divisor
def lcm(a: int, b: int) -> int:
    return a // math.gcd(a, b) * b

# another one that is used often is the modular inverse
# this extends the Euclidean algorithm
# useful function - returns x value in a*x = 1 (mod m)
def modInv(a: int, m: int) -> int:
    g = math.gcd(a, m)
    if g != 1:
        raise ValueError(f"No inverse for {a} mod {m} (gcd={g})")
    return pow(a, -1, m)
    
# next we want to make sure we can generate random numbers
def getRandom(n: int) -> int:
    sr = random.SystemRandom()
    while True:
        r = sr.randrange(1, n)
        if math.gcd(r, n) == 1:
            return r


# ---------------------------------------
#         Paillier Implementation
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

# Formula from info:
# c = (g^m * r^n) mod n^2
# Inputs:
# we need m for message in constraints (0 <= m < n)
# r is random integer in Z_N^* 
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


# Formula from info:
# m = L(c^λ mod n^2) * μ mod n
# Where L(u) = (u - 1) / n
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


# ----------------------------------------------
# Samll Demonstration (for testing purposes)
# ----------------------------------------------
if __name__ == "__main__":
    # output text
    print("=== Paillier Cryptosystem Draft Demo Output ===")

    # Will run steps from information provided

    # Step 1: Key generation
    pub, priv = generatePaillierKey(bits=64)
    print(f"Public Key: {pub}")
    print(f"Private Key: {priv}\n")

    # Step 2: Encrypt a sample "vote" (e.g., 1 = candidate A)
    vote = 1
    c = paillier_encrypt(pub, vote)
    print(f"Encrypted vote (ciphertext): {c}\n")

    # Step 3: Decrypt to confirm correctness
    decrypted_vote = paillier_decrypt(pub, priv, c)
    print(f"Decrypted vote (plaintext): {decrypted_vote}\n")