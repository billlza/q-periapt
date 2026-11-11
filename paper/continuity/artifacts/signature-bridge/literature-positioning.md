# Positioning of the reservation-to-ordinary bridge

Primary-source check, 8 November 2026.

Nonce-based and hedged signature security provide the background for this
connection. Bellare and Tackmann develop nonce-based cryptography and hedged
extractors, including nonce-based signatures. Aranha, Orlandi, Takahashi and
Zaverucha analyze hedged Fiat–Shamir signatures under nonce and fault attacks.
Grilo, Hövelmanns, Hülsing and Majenz give a quantum random-oracle treatment of
nonce and fault attacks for the hedged Fiat–Shamir transform. Kosuge and Xagawa
analyze fault-injection security for the structured randomness generation in
ML-DSA. These works should be cited when introducing the hedging bridge.

The contribution developed here is the exact connection from the manuscript's
persistent reservation execution to ordinary native hedged-signature EUF.
The connection preserves openings before execution, selection among opened
reservations, duplicate effective inputs, private computations followed by
failed publication, exact replay, owner aliases, and non-target disclosure.
For the pinned ML-DSA implementation, it compares complete experiments with
one shared prefix-consistent SHAKE256 XOF, including the hidden seed expansion
and the secret-prefix hedge slice. The source call-length inventory makes the
query loss explicit, and the resulting bound can be substituted into the
executed-source attribution theorem.

This is a positive description of the result established in this manuscript.
The generic hedging construction and security under nonce exposure are placed
in their existing literature. The sources inspected here support that
positioning; no priority claim or claim about an omitted case in another
paper is inferred from an abstract. The 2025 paper's publisher and ePrint
abstracts were available, while its full PDF was not retrieved in this check.

## Primary references

- Mihir Bellare and Björn Tackmann. *Nonce-Based Cryptography: Retaining
  Security when Randomness Fails*. EUROCRYPT 2016, pp. 729–757.
  DOI: https://doi.org/10.1007/978-3-662-49890-3_28.
  Author-supplied record: https://eprint.iacr.org/2016/290.
- Diego F. Aranha, Claudio Orlandi, Akira Takahashi and Greg Zaverucha.
  *Security of Hedged Fiat–Shamir Signatures under Fault Attacks*.
  EUROCRYPT 2020, pp. 644–674.
  DOI: https://doi.org/10.1007/978-3-030-45721-1_23.
  Author page: https://dfaranha.github.io/publication/aranhao0z20/.
  Full-paper record: https://eprint.iacr.org/2019/956.
- Alex B. Grilo, Kathrin Hövelmanns, Andreas Hülsing and Christian Majenz.
  *Tight Adaptive Reprogramming in the QROM*. ASIACRYPT 2021, pp. 637–667.
  DOI: https://doi.org/10.1007/978-3-030-92062-3_22.
  Author-supplied record: https://eprint.iacr.org/2020/1361.
- Haruhisa Kosuge and Keita Xagawa. *The Security of ML-DSA Against
  Fault-Injection Attacks*. ASIACRYPT 2025, pp. 641–674.
  Publisher: https://doi.org/10.1007/978-981-95-5096-8_20.
  Author-supplied record: https://eprint.iacr.org/2025/904.

The new proof also cites FIPS 204 for the algorithm and Bennett, Bernstein,
Brassard and Vazirani for the underlying quantum query hybrid. The direct
hidden-support calculation is written out in the proof rather than delegated
to the citation.
