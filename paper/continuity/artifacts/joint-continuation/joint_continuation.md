# A joint continuation for a recovered epoch and its first message

Frozen version: v0.3, 2026-11-07. Complete proof with bounded traffic allocations; the independent review binds these frozen source files separately.

## 1. Result and exact scope

This note proves a finite, candidate-local key-schedule composition. It starts with one recovered epoch root sampled uniformly and independently of the shared SHA-256 compression oracle, before any use of that root. It reaches a game in which the selected direction's first message key is freshly uniform at installation and the continuation is recomputed consistently. The continuation retains the real confirmation MACs, real ACK generation and chosen-input verification, disclosed later contributions, and disclosed successor roots. It may also disclose the selected chain's next seed. The root, traffic and chain stages use the same public compression oracle throughout.

The new result is the composition and its concrete simulator. The individual shared-root HMAC bound, single-call root-initialization bound and exact HKDF-Expand normalization were proved in the existing notes cited in Section 12; they are inputs, not new results here. The result is for the typed interface below. Applying it to a native candidate-local game uses that game's actual source correspondence and preserves its original eligibility and projection accounting.

The statement is not that a root remains real-or-random when the complete future view is fixed. Every hybrid regenerates its continuation. In particular, the disclosed successor root retains its prescribed relationship with the successor contribution in that hybrid, and all control signatures authenticate the newly generated bodies.

## 2. Primitive interfaces and notation

Let \(n=256\) and let
\[
h:\{0,1\}^{512}\times\{0,1\}^{256}\longrightarrow\{0,1\}^{256}
\]
be one public quantum random oracle, with message block first and chaining value second. \(F(k,m)\) is the actual 32-byte-key HMAC-SHA256 construction over \(h\), including its consumed-key-pad length offset. \(\operatorname{Expand}(p,I,l)\) is the actual HKDF-Expand under PRK \(p\), complete information string \(I\) and byte length \(l\). Every ordinary oracle query made by preparation, the adversary, honest code, simulations and the terminal test is counted. Initial auxiliary state is independent of \(h\) and the designated fresh key; oracle-dependent preparation is executed, not supplied as free advice.

Write
\[
\begin{aligned}
\alpha(a)&=h((a\Vert0^{32})\mathbin\oplus\mathtt{36}^{64},\mathrm{IV}),\\
\beta(a)&=h((a\Vert0^{32})\mathbin\oplus\mathtt{5c}^{64},\mathrm{IV}),\\
\Gamma(a)&=(\alpha(a),\beta(a)).
\end{aligned}
\]
The exponents in these byte encodings count bytes. We use three operational error parameters.

1. \(\epsilon_{\rm Hjoint}(C,T,q,L)\) bounds the output-bit probability gap between \(\operatorname{Col}(a)=F(a,R)\), \(\operatorname{Row}(m)=F(R,m)\) for uniform hidden \(R\), and \(\operatorname{Col}(a)=V(\Gamma(a))\), \(\operatorname{Row}(m)=U(m)\). There are at most \(C\) classical column calls, \(T\) classical row calls, \(|m|\le L\), and \(q\) ordinary compression queries. \(U,V\) are independent private random functions independent of \(h\); equal inputs are cached. This is the independent-table ideal in the retained shared-root lemma, before its optional cross-pair repair.
2. \(\epsilon_{\rm Hrow}(T,q,L)\) bounds real \(F(P,m)\) versus a private random function \(W(m)\), for one uniform hidden 32-byte \(P\), at most \(T\) adaptive classical row queries and the stated ordinary-query and length bounds. Exact repeats agree. This is a multi-message row interface, wider than the one-immutable-transcript report interface.
3. \(\epsilon_{\rm Hcol}(q)\) bounds one distinct zero-salt call \(F(0,S)\) for uniform hidden 32-byte \(S\) versus one independently uniform 32-byte reply, with \(q\) ordinary public-compression queries. Repeated use of the same Extract retrieves its reply.

These bounds concern a complete interactive algorithm's terminal bit. They do not fix an already published secret-dependent future transcript or expose the hidden input/private tables. Section 10 gives concrete admissible compression-QROM instantiations from the retained lemmas.

## 3. Joint continuation interface

### 3.1 Initialization and root uses

The full execution begins from independent \(h\), auxiliary state and a uniform 32-byte \(R\); \(R\) can equivalently be presampled and withheld until epoch creation. Preparation may choose the public session identifier \(\mathit{sid}\), context and transcript state using \(h\). The old root, old saved state and wrapping keys may already be known. Preparation does not use the withheld \(R\).

The epoch controller's only raw uses of \(R\) are
\[
P_0=F(0,R),\qquad P_s=F(\mathit{sid},R),\qquad
P_x^+=F(R,S_x^+).                                      \tag{1}
\]
Both salts are 32 bytes. The 32-byte successor contributions \(S_x^+\) are supplied by known local computation. They may be disclosed, adaptively chosen from the available view and repeated; at most \(t_+\) distinct successor row inputs occur. The controller can compute
\[
R_x^+=\operatorname{Expand}(P_x^+,I_x^+,32),             \tag{2}
\]
for known information strings, reveal these successor roots, and execute arbitrary subsequent computation from them with the same \(h\). It may also disclose the successor PRKs: they are admitted row outputs. Equal \((S_x^+,I_x^+)\) retain their result. This permits meaningful later disclosure while keeping the designated current \(R\) private.

The PRKs \(P_0,P_s\) are used only through the Expands below. They are not returned, compared as raw secret bytes, hashed through another interface, or included in a publicly readable serialization. Raw current-root/PRK/selected-seed/key projections are outside this interface. In a stopped candidate-local application, such a requested projection must already be handled by its justified stop or actual projection residual; this theorem supplies neither a permission nor a new eligibility definition.

Other keys, signatures, hash calls, record metadata and state-machine operations are produced by explicit local algorithms using known inputs, the declared interfaces and the same public oracles. In particular confirmation and ACK keys may be used in arbitrarily many real MAC computations and verifications. No verification is changed to a comparison with one cached original tag.

### 3.2 Confirmation and traffic

Let the exact domain strings be:

- \(D=\texttt{Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/}\), 40 bytes;
- \(DM=\texttt{Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/}\), 43 bytes.

The confirmation information strings are
\[
\begin{aligned}
I_r&=D\Vert\texttt{responder-confirmation},\\
I_f&=D\Vert\texttt{final-confirmation},\\
I_a&=D\Vert\texttt{receipt-confirmation}.
\end{aligned}
\]
When needed, compute \(k_d=\operatorname{Expand}(P_0,I_d,32)\) for \(d\in\{r,f,a\}\), then perform the real confirmation MACs and verifications. Associated signatures and state transitions are recomputed from these results.

At most \(M\ge1\) distinct traffic information strings have the native form
\[
\begin{split}
I_T={}&D\Vert\texttt{epoch-traffic/HKDF-SHA256/ChaCha20Poly1305/}\\
 &\Vert\mathit{context}_{32}\Vert\mathrm{BE64}(e)
 \Vert\mathit{transcriptDigest}_{32}.                   \tag{3}
\end{split}
\]
The running controller chooses each string from available inputs. Natively the final field hashes the complete signed offer and response wires. Thus \(I_T\) may depend on returned root-derived confirmation tags and their signatures; it is not required to be independent of them. Every equal complete information string reuses its existing table entry, regardless of which endpoint or wire representation requested it. No single-wire or cross-endpoint uniqueness premise is imposed.

At the first allocation of one new information string \(I^*\), designate that entry and a global direction \(d^*\in\{1,2\}\) as the target, **before any of its blocks are produced**. The designation may use the available prefix; it cannot reclassify a previously allocated entry as fresh. Later aliases of \(I^*\) retain the target's protection. This is a profile for the first send under a designated fresh traffic allocation, not a claim about an unrestricted retrospective choice among already used traffic keys.

Split the 128-byte Expand into four full blocks:
\[
(s_{I,1},s_{I,2},a_{I,1},a_{I,2})=\operatorname{Expand}(P_s,I,128). \tag{4}
\]
Roles 1 and 2 interchange send/receive positions as in the native material assignment. The designated seed is \(s^*=s_{I^*,d^*}\), used only in the first selected chain step below. The opposite seed, both target ACK keys, and every block at a different complete information string may be disclosed and used in known continuation. A repeated \(I^*\) never becomes a different, disclosable entry. Confirmation keys may also be disclosed; their privacy is not this theorem's conclusion.

The three confirmation information strings and \(I_T\) are different for all context/digest values. Their fixed labels and lengths distinguish them. This holds even if \(\mathit{sid}=0\), or distinct salts have equal \(\Gamma\): a shared Extract PRK then feeds different Expand information strings.

### 3.3 Selected chain step

The selected direction's first message has index \(0\). Put
\[
\begin{aligned}
 I_M&=DM\Vert\texttt{chain}\Vert\mathrm{BE64}(0),\\
 P_M&=F(0,s^*),\\
 (s',K)&=\operatorname{Expand}(P_M,I_M,64).              \tag{5}
\end{aligned}
\]
The selected old seed has no other raw use. Exact recomputation of this original step reuses its outputs. The next seed \(s'\) may be returned in full; all later chain computation can use the actual algorithms and the same public oracle. The selected message key \(K\) is used only through the declared application encryption/decryption interface. It is neither released nor used by another raw-key-dependent public computation.

Private storage is permitted through an already established opaque interface. An intact post-reservation native record acquisition can be stopped using the existing permanent-failure certificate when its hypotheses hold. An independently readable fragment is assessed by its actual returned bytes. The optional successor-root and next-seed projections here are computable and need not be stopped merely because they are projections.

Live keys may equal zero. The native constructors accept all 32-byte live root/seed/key values. Zero checks for closed/resolved traffic concern fields explicitly overwritten with zero; those known erasure markers are retained by the controller. There is no hidden zero-rejection condition or associated loss.

## 4. Exact Expand separation with adaptive information

**Lemma 1 (fresh traffic blocks despite confirmation-dependent information).**
Suppose each PRK class among \(\Gamma(0),\Gamma(\mathit{sid})\) is available only through HKDF-Expand, and its HMAC row has been replaced by its own independent private random function. This interface is exactly equivalent to independent uniform block tables indexed by (PRK class, complete information string, block index), with shared prefixes on length extension. Information strings may be chosen adaptively from previous outputs and arbitrary computation with \(h\).

The four designated traffic blocks, at their first installation, are consequently mutually independent and independent of \(h\), the entire prior available state, the confirmation keys and all previously allocated blocks. In particular, each selected block is independent of the other newly allocated target blocks at that boundary. The entry is marked before its blocks are produced, so the selected seed may be presampled independently and withheld until its first permitted use. This independence is asserted at installation, not after fixing a later ciphertext or a future adaptively selected table entry.

**Proof.**
For a private row \(W\), HKDF queries
\[
m_{I,1}=I\Vert\mathrm{byte}(1),\qquad
m_{I,j}=T_{I,j-1}\Vert I\Vert\mathrm{byte}(j)\quad(j\ge2),
\]
where \(T_{I,j}=W(m_{I,j})\) is exactly 32 bytes. Different counters separate inputs by their final byte. For counter 1, input equality implies equal \(I\). For any common counter at least 2, deleting the fixed-width 32-byte prefix and final counter also gives equal \(I\). Thus distinct \((I,j)\) pairs produce distinct inputs for every preceding output assignment; equal pairs retrieve the same input and output inductively. This is a pointwise argument, requiring no independence of the information selection rule.

Sample each new row reply as its table block. Repeated or shortened Expands retrieve the same prefix. Different PRK classes have independent tables. The confirmation calls have not touched the traffic entries because their complete information strings differ. Previously allocated traffic entries also have different full information strings from the marked new \(I^*\). Its blocks are fresh even when earlier tags, signatures or other traffic outputs determined \(I^*\).

This rewrite also removes an important hidden dependence: direct HKDF places a previous output block into the next private row input. As that row has no additional interface, the exact block-table representation eliminates these internal inputs. The selected seed can therefore enter (5) as a hidden-input challenge without leaving an unmodeled parent-row channel containing it. Public quantum queries remain unchanged; only private classical row replies are coupled. ∎

## 5. Joint schedule theorem

Let \(G_R\) implement Section 3 with actual HMAC/HKDF and a uniform root at the stated creation boundary. An *available terminal test* reads the public view, declared event ledger, locally computable controller outputs and its own independent test randomness. It has no extra access to designated private root, PRK, seed, message-key or oracle-table contents.

Define \(G_{\rm leaf}\) constructively:

1. Replace (1) with independent private tables \(V(\Gamma(a))\) and \(U(S_x^+)\).
2. For each of at most two \(\Gamma\) classes, implement its Expands by Lemma 1's independent block table. Preserve aliases, including zero session ID. Use the resulting confirmation and ACK keys in real algorithms. Compute successor roots by real Expand from the returned \(U\) values and run their entire permitted continuation.
3. For the selected chain step, sample \(s',K\) independently and uniformly as two cached blocks. Use \(s'\) in the real future chain. Feed \(K\) only to the selected application encryption/decryption interface.

Original-operation and retry identities persist. Checks, signatures, commitments already specified by the typed interface, ciphertexts and later outputs are recomputed in their current game. A control wire is not frozen while its generating key is changed.

For the five reductions below, let \(q_R,q_0,q_1,q_s,q_M\) bound **all** ordinary compression queries, including preparation and future continuation. Set
\[
\begin{aligned}
\Delta_{\rm sched}=\min\{1,\;&
\epsilon_{\rm Hjoint}(2,t_+,q_R,32)\\
&+\epsilon_{\rm Hrow}(3+4M,q_0,188)
+\epsilon_{\rm Hrow}(4M,q_1,188)\\
&+\epsilon_{\rm Hcol}(q_s)
+\epsilon_{\rm Hrow}(2,q_M,89)\}.                        \tag{6}
\end{aligned}
\]
If the interface itself rules out a second PRK class, omit its row term. The first class has at most \(3+4M\) distinct row inputs and the second at most \(4M\); their total is at most \(3+4M\). These separate worst-case bounds are safe when class equality is decided during oracle-dependent preparation. They do not condition a primitive theorem on an unproved fixed-oracle collision event.

**Theorem 2 (joint separation of a selected message leaf).**
For every available terminal bit \(D\),
\[
|\Pr[G_R:D=1]-\Pr[G_{\rm leaf}:D=1]|
\le\Delta_{\rm sched}.                                \tag{7}
\]
For a common available score \(Z\in[-1,1]\),
\[
|\mathbb E_{G_R}Z-\mathbb E_{G_{\rm leaf}}Z|
\le2\Delta_{\rm sched}.                               \tag{8}
\]

The ideal message key is independent at installation. This concerns a fully regenerated continuation, not independence of the key and a ciphertext subsequently computed under it.

### Proof

**Root hop.**
A joint-game distinguisher executes all preparation, queries its columns on known salts \(0,\mathit{sid}\), and its row on each known \(S_x^+\), caching repeats. It executes every other HMAC, HKDF, signature, record-interface and application operation using returned values and the same public oracle. It never needs raw \(R\). Its real world is \(G_R\); its ideal world gives step 1 above. The first term of (6) bounds this comparison. Successor PRKs are known replies, so their actual Expand and disclosed successor roots can be computed directly.

This uses the independent-table ideal \(I\) of the retained shared-root proof, already reached by its first three hybrids. We do not claim the separately repaired ideal \(J\), so do not need its extra cross-pair term. Accidental classical equality with hidden \(R\) is not excluded.

**Two column-PRK row hops.**
Privately preallocate the zero-salt PRK class if necessary, and allocate the session class if its \(\Gamma\) differs. This harmless deferred-sampling choice does not depend on the order of visible calls. For a designated class, assign the row primitive's hidden uniform key to that class's first private \(V\) entry, presampled and withheld until creation. The class identifier is computed from known salts and \(h\), without inspecting its private \(V\) value. A repeated \(\Gamma\) reuses the same handle.

For its Expand calls, query the challenge row on the actual inputs, computing each next input from the known information string and previous reply. All output blocks, including confirmation keys and traffic seeds, are therefore known to the reduction even though its PRK is not. It can execute the resulting MACs, verifications, signatures and continuation honestly. Other classes are sampled locally and evaluated using the real or already ideal row prescribed by that hybrid. Every known-key HMAC uses the same \(h\) and counts in \(q_0\) or \(q_1\). A never-allocated class causes no challenge call.

There are three one-block confirmation Expands, with HMAC input lengths 63, 59 and 61, and at most \(M\) four-block traffic Expands, each with lengths 156, 188, 188 and 188. The zero-salt class has at most \(3+4M\) calls of maximum length 188; a distinct session class has at most \(4M\). Exact repeats and complete-information aliases add no fresh row inputs.

Different independent \(V\) entries may happen to have equal numeric key values. The reduction does not compare values or assume inequality: in a real hybrid, known-key HMAC computation uses the same oracle, including any overlap with the challenge key, and is counted as ordinary work. In the ideal hybrid the selected class has its declared private row. This is the primitive experiment's change, not an assertion that equal real HMAC keys define distinct real functions. Deliberate \(\Gamma\) aliases, unlike independently sampled coincident values, share their row in every hybrid.

After both row hops, apply Lemma 1 exactly. Its adaptive-information argument covers the response-confirmation dependence of the traffic transcript.

**Selected-seed Extract hop.**
After this normalization, \(s^*\) is an independent uniform block with no residual parent-row input channel. The reduction presamples the column primitive's hidden seed, then installs it at the newly marked entry and direction before that entry's blocks are produced. No earlier equal-info entry exists, and subsequent equal-info aliases retain the same protected handle. Every other traffic/confirmation block is sampled locally. Its only raw use is \(F(0,s^*)\), answered by the primitive column. Successor-root disclosure, other traffic material, ACKs and all remaining continuation are computed from known values. The real world matches (5); the ideal reply is independent uniform \(P_M\). The cost is \(\epsilon_{\rm Hcol}(q_s)\).

**Selected-chain row hop.**
That \(P_M\) is fresh independently of the common oracle and earlier state. Embed the uniform row key there, perform the two actual Expand queries, and run the continuation from their replies. The two messages have lengths 57 and 89. No other operation reads the PRK. The final row term in (6) bounds this change. Exact Expand normalization makes the two output blocks independent \(s',K\), without another error. Revealing \(s'\) and computing later chain keys from it needs neither \(P_M\) nor raw \(K\).

Each reduction executes preparation and regenerates the later view; none fixes an oracle-correlated prefix for free. Summing the five bit gaps proves (7). The randomized terminal bit that is 1 with probability \((Z+1)/2\) gives (8), using the same available inputs and its independent test coins. For the later left-or-right score, fix either application challenge bit \(b\), apply this bound to that fixed-bit controller, then average. Equivalently each HMAC reduction may sample its own independent application bit. This does not give a distinguisher access to a hidden primitive key or nonce. ∎

## 6. One-message confidentiality

Use a single-key, one-encryption left-or-right AEAD experiment with classical interfaces, uniform 32-byte key, nonce \(0^{96}\), and the same additional public oracle \(h\). The challenge uses equal-length \(m_0,m_1\), common associated data, and uniform bit \(b\). A decryption interface may be queried before and after encryption. It returns real plaintext or failure except that the exact challenge ciphertext with its challenge nonce and associated data returns a distinguished authenticated marker. Let \(\epsilon_{\rm AEAD}\) be the ordinary absolute guessing advantage over \(1/2\). The reduction and all continuation belong to its computational and query class. If an implementation reveals finer decryption outcomes, that outcome interface must be represented.

This is an explicit one-use AEAD assumption for ChaCha20-Poly1305 in the chosen model, not a consequence of HMAC security. An encryption-only profile instead uses the corresponding one-use privacy game.

The application controller has the following interface:

- An honest application creates the challenge send origin. The adversary receives ciphertext, metadata, status, network authentication/error outcomes and ACK traffic.
- Repeats of that origin reuse the encryption result, including reconstruction after a crash before commit. The cache is allocated at the **first private computation**, not release.
- The adversary may call the plaintext-free \(\operatorname{resume\_message}(id)\). It is not given a plaintext-bearing send-intent equality query for this challenge ID.
- Challenge plaintext delivery and any resolution output containing it go privately to the honest application. No additional public behavior is a function of that payload beyond the declared encryption interface and common public metadata. Exact challenge reception is simulated using the authenticated marker and metadata.
- Other ciphertexts, scope checks, ACK verification and state changes follow the real algorithms through known state and the specified decryption interface. Any additional public raw-payload or payload-predicate return is separately assessed, not erased by changing record eligibility.

The selected origin includes the marked traffic material's original allocation and authoritative owner/history, the global direction and logical index 0. Within that fixed native traffic owner this is the existing (direction, original traffic epoch, index) origin; different full-information allocations are never merged merely because their epoch numbers agree. Existing native send-origin normalization says all this origin's private recomputations use the same key, nonce, plaintext and associated data; it does **not** say native code invokes encryption once. The simulator makes one primitive query and caches it through all recomputations and releases.

For an unknown LR bit, the actual payload and its private send-intent digest are opaque application handles. The retained SendPlan carries the payload and Outgoing carries the digest. Neither is published by status or historical metadata; a full post-cut record acquisition is treated by the existing candidate-local stop. Legitimate Resume uses the same original handle, while a public direct fragment or guess-Send query is a separate application projection. This explains how the encryption reduction avoids needing the challenge plaintext.

**Corollary 3 (selected first-message confidentiality).**
Let \(A\) be a Boolean terminal event computable from the available public view and declared ledger **without reading the hidden AEAD challenge bit \(b\)**, including unchanged eligibility/attribution supplied by a valid candidate-local interface. If \(g\) is the guess and
\[
Z=\mathbf1_A(2\mathbf1[g=b]-1),
\]
then
\[
|\mathbb E_{G_R}Z|
\le2\Delta_{\rm sched}+2\epsilon_{\rm AEAD}.             \tag{9}
\]

**Proof.**
Apply Theorem 2 separately for each fixed application bit and average, changing the score by at most \(2\Delta_{\rm sched}\). In \(G_{\rm leaf}\), implement the selected encryption/decryption using the AEAD challenger. Sample the next seed and every other independent block locally, and perform real confirmation, ACK, successor-root and subsequent-chain computations with those known values and the same oracle. Cache the first encryption reply even before its release. The challenge key has no other use. Exact challenge decryption uses the authenticated marker for public transitions; other decryption queries go to the challenger.

At the end, return \(g\) if \(A\) holds and an independent fair guess otherwise. The resulting centered success is exactly \(\mathbb E Z\), bounded by \(2\epsilon_{\rm AEAD}\). Combining the two steps proves (9). ∎

No pairwise-unequal-keys premise is needed. Other sampled keys are known and honestly processed by the reduction. Coincidence with the hidden message key lies within the primitive game and its computational budget.

**Concrete same-ID counterexample.**
If the public interface also returns \(\operatorname{send\_message}(id,m,ad)\)'s existing-ID intent check, choose equal-length \(m_0,m_1\) with different native intent digests. Immediately after the committed challenge, retry its ID with \(m_0\). The \(b=0\) branch returns the retained result, while \(b=1\) returns conflict. This perfectly reveals the bit without any target entropy or record acquisition. It identifies the wider application interface that changes the confidentiality experiment. The admitted network profile gives this actor Resume; the honest application retains the plaintext-bearing API.

## 7. Entry from a recovered contribution

Section 3's uniform value is the epoch root **after** \(\operatorname{derive\_root}\), not its KEM input. It is not directly asserted for native state.

There is a separately proved entry route. Suppose one combined contribution \(S\) is uniform and independent of \(h\) and initial auxiliary state. Counted preparation may choose and disclose the old root \(r\), and compute the public response core, but does not otherwise use \(S\). Execute
\[
\begin{aligned}
P&=F(r,S),\\
I_R&=D\Vert\texttt{pending-root/HKDF-SHA256/}
       \Vert\operatorname{hash}(\texttt{response-core},\mathit{core}),\\
R&=F(P,I_R\Vert\mathtt{01}).                           \tag{10}
\end{aligned}
\]
The information length is 97 bytes and its row message is 98 bytes. Endpoint recomputation and retries reuse this single original Extract/Expand. Neither \(S\) nor \(P\) has another raw use or disclosure; an already justified opaque record layer may retain their representations without returning them.

Let \(\Delta_{\rm init}\) be the retained single-Extract/Expand initialization bound with the complete controller above as continuation. Its hidden-message column hop produces independent \(P\); its hidden-key row hop produces independent \(R\). The latter first reply can be presampled and withheld, giving precisely Section 3's joint initialization. Every confirmation, signature, traffic and successor computation follows the replacement.

**Corollary 4 (known old root and a uniform recovered contribution).**
Under that exact entry interface,
\[
|\mathbb E Z|
\le2\Delta_{\rm init}+2\Delta_{\rm sched}
   +2\epsilon_{\rm AEAD}.                              \tag{11}
\]

**Proof.**
Use the existing root-initialization reduction with Sections 3 and 6 as its continuation, followed by Corollary 3. The continuation does not otherwise use the entry secret or PRK and all its oracle work is counted. It regenerates the complete root-dependent view, so no already published tag or wire is frozen during the replacement. ∎

A component-KEM replacement and the ContextBound hidden-input hash hop may precede (10) when their actual interfaces are met. This note does not equate the real combined KEM output with uniform \(S\) without those hops.

## 8. Candidate-local composition

For candidate \(j\), let its post-correspondence and post-component/combiner continuation match the stated source/application interface. Keep the common native score and original eligibility. The remaining ideal-contribution score then satisfies
\[
|b_j|\le2\Delta_{{\rm init},j}
       +2\Delta_{{\rm sched},j}
       +2\epsilon_{{\rm AEAD},j}.                      \tag{12}
\]
This replaces that specified profile's continuation residual by a proved conditional bound. The actual \(\rho_j\), authentication terms, component errors and original-game projection residual remain in their established locations. If the ideal component game still uses the real ContextBound combiner, its actual score error precedes (12).

Pre-cut captures and old wrapping-key disclosure are compatible with the profile. Intact matching post-reservation records have the existing permanent-failure certificate before their raw return. Optional successor-root and next-seed projections can be computed here instead. These are different mechanisms: a projection is not renamed a Snapshot, and required storage comparisons do not become free.

## 9. Native call facts

Source read: local \(\texttt{q-periapt-ci}\) at \(\texttt{1c68aa666db22d36ee136be1ec712545a9e74f03}\); the evidence agent binds relevant file identities to the earlier protocol pin. Complete trace correspondence remains distinct from these call facts.

| Source location under the candidate | Fact used |
| --- | --- |
| contract.rs:18–20 | Exact 40-byte rekey and 43-byte message domains. |
| durable/messages/rekey/response.rs:133–164 | Old-root Extract, 97-byte root info and zero-salt responder-confirmation derivation. |
| durable/messages/rekey/completion.rs:438–460 | Final and receipt share zero-salt Extract, with different Expand labels. |
| durable/messages/rekey/completion.rs:646–678 | Session-salt 128-byte traffic Expand; full offer/response-wire digest in its 155-byte info. |
| durable/messages/traffic.rs:61–103 | Four 32-byte blocks, role-dependent assignment, all live values accepted. |
| durable/messages.rs:201–217 | Zero-salt chain Extract and 64-byte Expand with 56-byte info. |
| durable/messages/traffic.rs:396–450 | Existing-ID send-intent test, cached committed retry, zero-nonce AEAD. |
| durable/messages/traffic.rs:452–550 | Real chosen-ciphertext verification, actual scope checks, retries and failure state semantics. |
| durable/messages/acknowledgement.rs:72–112 | Arbitrary ACK wire receives actual HMAC verification after parse/scope checks. |

Sending after local FinalReady is permitted; the theorem does not require prior peer receipt. Root-only projections must use the actual installed root's owner, not just confirmed_epoch: the proposer already installs its new root at FinalReady. Next-seed projections refer to the post-commit traffic field with sent=1, not an old durable seed before private computation has committed.

## 10. Concrete compression-QROM bounds

Put
\[
\Phi_{256}(d,Q)=\min\{1,\,
4\sqrt{2d^2Q/2^{256}}+4\sqrt{2Q^2d/2^{256}}\},
\qquad
\ell(L)=1+\lceil(L+9)/64\rceil.
\]
The admitted length is \(L\le2^{61}-65\). Let \(E_{\rm NMAC}\) and \(E_{F_1}\) be the published bounds, with their original regimes and constants, used by the retained shared-root proof. It supplies
\[
\begin{aligned}
\epsilon_{\rm Hjoint}(C,T,q,L)\le\min\{1,\;&
\Phi_{256}(C+2,q+3C+\ell(L)T)\\
&+E_{\rm NMAC}(T,q+3C,\ell(L))
+E_{F_1}(C,q+2C)\},\\
\epsilon_{\rm Hrow}(T,q,L)\le\min\{1,\;&
\Phi_{256}(2,q+\ell(L)T)
+E_{\rm NMAC}(T,q,\ell(L))\},\\
\epsilon_{\rm Hcol}(q)\le\min\{1,\;&
\Phi_{256}(3,q+3)+E_{F_1}(1,q+2)\}.                     \tag{13}
\end{aligned}
\]
Here \(\ell(32)=2\), \(\ell(188)=5\), and \(\ell(89)=3\). These are HMAC message lengths, including the previous HKDF block where applicable, not just information lengths.

If \(B\) bounds all other ordinary \(h\) work in the entry reductions, the retained conservative initialization bound is
\[
\Delta_{\rm init}\le\min\{1,\,
\Phi_{256}(3,B+8)+E_{F_1}(1,B+7)
+\Phi_{256}(2,B+5)+E_{\rm NMAC}(1,B+2,3)\}.             \tag{14}
\]
No numerical security-bit estimate is extracted from unspecified asymptotic constants. These bounds are in the compression-QROM model with the actual HMAC/HKDF encodings.

## 11. Contribution of this increment

The proved composition handles confirmation-dependent traffic information and the shared zero-salt case. It then turns a traffic block into a valid hidden-input challenge: exact private-row normalization removes the parent inputs containing that block, so the next stage's independent-input premise is earned. Finally it retains computable successor-root and next-seed disclosure, real confirmation/ACK verification and one-message encryption under a shared compression oracle.

The preceding source/component correspondence is not renamed as this theorem. The application boundary specifies which actor receives plaintext-bearing returns; it does not redefine eligibility. The same-ID counterexample identifies exactly the wider public interface that would require separate treatment.

## 12. Audit references

Existing proof inputs:

- q-periapt-ci/docs/continuity/SHARED_ROOT_HMAC_V1.md — simultaneous row/column game and independent-table ideal.
- q-periapt-ci/docs/continuity/ROOT_EXTRACTION_QROM_V1.md — one actual Extract/Expand initialization with counted shared-oracle preparation.
- q-periapt-ci/docs/continuity/HKDF_EXPAND_TABLE_V1.md — exact complete-information/block-index normalization.
- q-periapt-ci/docs/continuity/AEAD_SEND_ORIGIN_V1.md — one encryption-oracle call per original send despite pre-release recomputation.
- q-periapt-ci/docs/continuity/COMPUTATIONAL_RECOVERY_V1.md — actual shared call graph and entry boundary.
- q-periapt-ci/docs/continuity/CONTEXTBOUND_SECRET_HOP_V1.md — separate post-component combiner hop.
- work/joc_round3/manuscript/artifacts/candidate-local/candidate_local_composition.md — common-native score and local stops/correspondence.

The retained primitive proofs use Don–Fehr–Huang, Theorem 2, <https://arxiv.org/pdf/2206.08132>, and Hosoyamada–Iwata, Propositions 4 and 6, <https://eprint.iacr.org/2021/774.pdf>. This note uses their stated existing interface instantiations; it does not replace their applicability conditions with a new informal assumption.
