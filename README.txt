Project: Secure Voting — Paillier Homomorphic Election System
==============================================================

Team Members
------------
- Amman, Ahmad
- Bruno Terceros, Jason
- Ngo, Hieu
- Sink, Connor

Overview
--------
This project demonstrates how the Paillier cryptosystem can be used to build a
privacy-preserving voting system capable of homomorphic tallying. Paillier’s
additive homomorphism allows encrypted votes to be combined without ever
decrypting individual ballots, preserving voter privacy.

Our project includes:
- Paillier key generation (educational prototype)
- Encryption and decryption functions
- Homomorphic addition using ciphertext multiplication
- A simple 0/1 election simulation
- A realistic multi-candidate election using the team members as candidates
- Clean modular organization across multiple Python files

Files
-----
- **Paillier_Prototype.py**  
  Early working prototype used during development. Kept for reference.

- **Paillier_Vote.py**  
  Main Paillier cryptosystem implementation: key generation, encryption,
  decryption, and helper utilities. Used by both election scripts.

- **Simple_Election.py**  
  Demonstrates a binary election (YES/NO or Candidate A vs Candidate B).
  Uses homomorphic encryption to tally votes privately.

- **Realistic_Election.py**  
  A full multi-candidate election with four candidates:
    - Amman, Ahmad
    - Bruno Terceros, Jason
    - Ngo, Hieu
    - Sink, Connor  
  Voters select exactly one candidate. All votes are encrypted, aggregated,
  and decrypted only once to reveal the final tally.

- **README.txt**  
  This documentation file.

Requirements
------------
- Python 3.8+  
  (Required for `pow(..., -1, mod)` built-in modular inverse support.)
- No external dependencies.

How to Run
----------
1. In terminal run python with:
2. Place all .py files in the same directory.
3. Open a terminal in that directory and run:

   Simple election:
       $ python Simple_Election.py

   Realistic election:
       $ python Realistic_Election.py

   Prototype (optional):
       $ python Paillier_Prototype.py

Each script will:
- generate Paillier keys,
- encrypt sample votes,
- homomorphically aggregate the encrypted ballots,
- decrypt only the final tally,
- display all steps clearly on the console.

Security Notes (IMPORTANT)
--------------------------
This project is **for academic and demonstration purposes only**.
It is intentionally insecure and should NOT be used in any real-world 
cryptographic application.

Major limitations include:
- Small, hard-coded prime numbers (NOT cryptographically safe)
- No zero-knowledge proofs (voters could submit invalid ciphertexts)
- No authentication of voters
- No secure randomness guarantees
- No threshold decryption (single point of failure)
- Not resistant to timing or side-channel attacks
- No bulletin board or audit logs

For a production-grade secure voting system, you would need:
- 2048-bit (or larger) primes generated with a trusted cryptographic library
- Zero-Knowledge Proofs to validate voter choices
- Threshold decryption (split private key among authorities)
- Secure randomness via OS CSPRNG
- Voter authentication and signatures
- Merkle-tree-based auditable public ledger
- Protocol-level defenses against replay and ballot duplication

Design Notes & Future Work
--------------------------
Potential improvements for extension:
- Add ZKPs such as Chaum–Pedersen proofs for valid vote encoding.
- Implement threshold Paillier using Shamir Secret Sharing.
- Add a verifiable bulletin board with Merkle proofs.
- Replace demo prime lists with true cryptographic prime generators.
- Build a GUI or web-based interface for a user-friendly voting demo.
- Integrate digital signatures for voter authentication.

Report
------
A separate written report accompanies this implementation. It should:
- Detail description of Paillier and history of voter security,
- Explain Paillier mathematically and conceptually,
- Describe the code structure and election workflow,
- Analyze security limitations and threats,
- Discuss improvements needed for a real secure voting system.
