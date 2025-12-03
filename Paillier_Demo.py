# Paillier_Demo.py
# controlled interactive demo for our cryptography presentation
# This Demonstrates:
#     - Single vote encryption/decryption
#     - Yes/No election with homomorphic tally
#     - Multi-candidate vector election using component-wise Paillier addition

# Things to note:
#     All demo modes rely on the Paillier cryptosystem:
#         Encryption: c = g^m * r^n (mod n^2)
#         Decryption: m = L(c^lambda (mod n^2)) * mu (mod n)
#         Homomorphism: E(m1) * E(m2) = E(m1 + m2)

# For the sake of the class, and python these demos run on SMALL PRIMES
#     for better security you could use bigger prime values

from Paillier_Vote import (
    generatePaillierKey,
    paillier_encrypt,
    paillier_decrypt,
    homomorphic_add,
    homomorphic_add_many
)

# ---------------------------------------------------
# REALISTIC MULTI-CANDIDATE ELECTION
# Vector Paillier Tally:
#  Jason    -> (1,0,0,0)
#  Connor   -> (0,1,0,0)
#  Ahmad    -> (0,0,1,0)
#  Hieu     -> (0,0,0,1)
# ---------------------------------------------------

from Realistic_Election import (
    CANDIDATES,
    encode_vote,
    encrypt_vector,
    add_vectors,
    decrypt_vector
)


def menu():
    print("\n===============================")
    print("   PAILLIER CRYPTO DEMO MENU   ")
    print("===============================\n")
    print("1) Encrypt/Decrypt a single vote")
    print("2) Run a simple YES/NO election")
    print("3) Run a multi-candidate election")
    print("4) Exit\n")

# ----------------------------------------------------------
# Mode 1: Single Demo Vote
# ----------------------------------------------------------
# This demonstrates:
#   • Generating Paillier keys
#   • Encrypting a single bit m is an element of {0,1}
#   • Verifying correctness by decrypting
#
# Under the hood:
#   Encryption uses:  c = g^m * r^n (mod n^2)
#   Decryption uses:  m = L(c^lamdba (mod n^2)) * mu (mod n)
#
# Purpose:
#   Show the mapping m → ciphertext → recovered m.
# ----------------------------------------------------------
def single_vote_demo():
    print("\n=== SINGLE VOTE DEMO ===")

    pub, priv = generatePaillierKey()
    print(f"Public Key n = {pub.n}, g = {pub.g}")

    while True:
        try:
            vote = int(input("Enter vote (0 or 1): "))
            if vote not in [0, 1]:
                raise ValueError
            break
        except ValueError:
            print("Invalid vote. Must be 0 or 1.")

    c = paillier_encrypt(pub, vote)
    print(f"Encrypted vote: {c}")
    decrypted = paillier_decrypt(pub, priv, c)
    print(f"Decrypted vote: {decrypted}\n")

# ------------------------------
# Mode 2: Simple yes/no election
# ------------------------------
# This demonstrates Paillier’s core homomorphic property:
#
#       E(m1) * E(m2) * ... * E(mk) = E(m1 + m2 + ... + mk)
#
# We:
#   • Collect voters' YES/NO votes (0 or 1)
#   • Encrypt each vote using c = g^m * r^n (mod n^2)
#   • Multiply ciphertexts to compute encryption of the sum
#   • Decrypt once to reveal the total YES count
#
# This demonstrates "additive homomorphism with single decryption."
# ----------------------------------------------------------
def simple_election_demo():
    print("\n=== SIMPLE YES/NO ELECTION ===")

    while True:
        try:
            n = int(input("How many voters? (1–20): "))
            if not (1 <= n <= 20):
                raise ValueError
            break
        except ValueError:
            print("Invalid number. Try again.")

    votes = []
    for i in range(n):
        while True:
            try:
                v = int(input(f" Vote {i+1} (0=No, 1=Yes): "))
                if v not in [0, 1]:
                    raise ValueError
                votes.append(v)
                break
            except ValueError:
                print("Invalid vote. Must be 0 or 1.")

    pub, priv = generatePaillierKey()
    print(f"\nPublic Key n = {pub.n}")

    ciphertexts = [paillier_encrypt(pub, v) for v in votes]
    aggregate = homomorphic_add_many(pub, ciphertexts)
    tally = paillier_decrypt(pub, priv, aggregate)

    print("\nEncrypted votes:", ciphertexts)
    print("Aggregated ciphertext:", aggregate)
    print("Decrypted total YES votes:", tally, "\n")


# ------------------------------
# Mode 3: Multi-candidate election
# ------------------------------
# Uses vector encoding + component-wise Paillier addition.
#
# For k candidates, each vote is encoded as a one-hot vector:
#       candidate i  →  (0,0,1,0,...)
#
# Encryption is applied to *each component*:
#       E(v) = (E(v1), E(v2), ..., E(vk))
#
# Homomorphic tally:
#       E_total[j] = (|-|) E(v_i[j])  over all voters i
#                  = E(sum of votes for candidate j)
#
# Final decryption recovers full vector tally.
#
# Mathematically identical to Yes/No case,
# but replicated across multiple coordinates.
# ----------------------------------------------------------
def multi_candidate_demo():
    print("\n=== MULTI-CANDIDATE ELECTION ===")
    pub, priv = generatePaillierKey()

    print("\nCandidates:")
    for i, c in enumerate(CANDIDATES):
        print(f" {i}. {c}")

    while True:
        try:
            n = int(input("How many voters? (1–20): "))
            if not (1 <= n <= 20):
                raise ValueError
            break
        except ValueError:
            print("Invalid number.")

    encrypted_tally = None

    for i in range(n):
        while True:
            try:
                choice = int(input(f" Vote {i+1}: choose candidate index 0–{len(CANDIDATES)-1}: "))
                if not (0 <= choice < len(CANDIDATES)):
                    raise ValueError
                break
            except ValueError:
                print("Invalid candidate index.")

        encoded = encode_vote(choice, len(CANDIDATES))
        encrypted = encrypt_vector(encoded, pub)

        encrypted_tally = encrypted if encrypted_tally is None else \
            add_vectors(encrypted_tally, encrypted, pub)

    print("\nDecrypting final tally...\n")
    tally = decrypt_vector(encrypted_tally, pub, priv)

    for name, count in zip(CANDIDATES, tally):
        print(f"{name}: {count} votes")

    winner = CANDIDATES[tally.index(max(tally))]
    print("\nWinner:", winner, "\n")


# ------------------------------
# MAIN LOOP
# ------------------------------
if __name__ == "__main__":
    while True:
        menu()
        choice = input("Select option: ")

        if choice == "1":
            single_vote_demo()
        elif choice == "2":
            simple_election_demo()
        elif choice == "3":
            multi_candidate_demo()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice.\n")