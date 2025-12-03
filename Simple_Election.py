from Paillier_Vote import (
    generatePaillierKey,
    paillier_encrypt,
    paillier_decrypt,
    homomorphic_add_many,
    getRandom
)

# ---------------------------------------------------
# SIMPLE 0/1 (NO/YES) ELECTION
# ---------------------------------------------------

def run_simple_election(votes):
    print("=== SIMPLE Paillier Election (0/1 votes) ===\n")

    # This will run steps from information provided

    # Step 1: Key generation
    pub, priv = generatePaillierKey()
    print(f"Public key: n={pub.n}, g={pub.g}")
    print(f"Private key: lambda={priv.lambda_}, mu={priv.mu}\n")

    print("VOTES:", votes)

    #  Step 2: Encrypt simple "vote" (e.g., 1 = candidate A)
    ciphertexts = []
    print("\nEncrypting votes...")
    for i, v in enumerate(votes):
        c = paillier_encrypt(pub, v)
        ciphertexts.append(c)
        print(f" Voter {i+1}: vote={v}, ciphertext={c}")

    # Step 3: Decrypt to confirm correctness
    #     but we are using both the homomorphic talling and
    #     fully decrypting

    # Homomorphic tally
    print("\nAggregating ciphertexts (homomorphic addition)...")
    aggregate = homomorphic_add_many(pub, ciphertexts)
    print("Aggregate ciphertext:", aggregate)

    # Decrypt tally
    tally = paillier_decrypt(pub, priv, aggregate)
    print("\nFINAL RESULT: total YES votes =", tally)

    return tally


if __name__ == "__main__":
    # Example
    votes = [1, 0, 1, 1, 0, 1]
    run_simple_election(votes)