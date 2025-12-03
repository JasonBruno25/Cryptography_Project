from Paillier_Vote import (
    PaillierPublicKey,
    PaillierPrivateKey,
    generatePaillierKey,
    getRandom,
    paillier_encrypt,
    paillier_decrypt,
    homomorphic_add
)
import random

# ---------------------------------------------------
# REALISTIC MULTI-CANDIDATE ELECTION
# Vector Paillier Tally:
#  Jason    -> (1,0,0,0)
#  Connor   -> (0,1,0,0)
#  Ahmad    -> (0,0,1,0)
#  Hieu     -> (0,0,0,1)
# ---------------------------------------------------

# ================================
# Candidates
# ================================
CANDIDATES = [
    "Amman, Ahmad",
    "Bruno Terceros, Jason",
    "Ngo, Hieu",
    "Sink, Connor"
]

# vote as one-hot vector
def encode_vote(index: int, num: int):
    v = [0] * num
    v[index] = 1
    return v


# encrypt each entry
def encrypt_vector(vec, pub):
    return [paillier_encrypt(pub, m) for m in vec]


# homomorphically add encryptions
def add_vectors(enc_vec_a, enc_vec_b, pub):
    return [homomorphic_add(pub, a, b) for a, b in zip(enc_vec_a, enc_vec_b)]


# decrypt each tally component
def decrypt_vector(enc_vec, pub, priv):
    return [paillier_decrypt(pub, priv, c) for c in enc_vec]


# ==========================================
# Election Simulation
# ==========================================
def run_realistic_election():

    print("\n======================================")
    print("      REALISTIC PAILLIER ELECTION     ")
    print("======================================\n")

    # Step 1: Generate keypair
    pub, priv = generatePaillierKey()
    print("Generated Paillier Keypair.")
    print(f"Public Key n = {pub.n}\n")

    num_candidates = len(CANDIDATES)

    print("Candidates:")
    for i, c in enumerate(CANDIDATES):
        print(f"  {i}. {c}")

    # Example voter list
    voters = [
        "Voter 1", "Voter 2", "Voter 3", "Voter 4",
        "Voter 5", "Voter 6", "Voter 7", "Voter 8"
    ]

    print("\nVoters:", ", ".join(voters), "\n")

    # Randomly generate votes
    print("Casting votes...\n")
    votes = []
    for voter in voters:
        choice = random.randint(0, num_candidates - 1)
        votes.append(choice)
        print(f"{voter} voted for: {CANDIDATES[choice]}")

    # Encrypt + tally
    print("\nEncrypting and homomorphically accumulating votes...\n")

    encrypted_tally = None

    for choice in votes:
        encoded = encode_vote(choice, num_candidates)
        encrypted = encrypt_vector(encoded, pub)

        if encrypted_tally is None:
            encrypted_tally = encrypted
        else:
            encrypted_tally = add_vectors(encrypted_tally, encrypted, pub)

    print("All votes encrypted and tallied.\n")

    # Decrypt the final vector tally
    print("Decrypting final results...\n")
    tally = decrypt_vector(encrypted_tally, pub, priv)

    print("========== FINAL RESULTS ==========")
    for name, count in zip(CANDIDATES, tally):
        print(f"{name}: {count} votes")

    # Identify winner
    winner_index = tally.index(max(tally))
    print("\nWinner:", CANDIDATES[winner_index])
    print("====================================\n")


# Run if executed directly
if __name__ == "__main__":
    run_realistic_election()