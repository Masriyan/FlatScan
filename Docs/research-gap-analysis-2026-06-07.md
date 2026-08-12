# Research vs FlatScan — Gap Analysis (working notes)

> **Note (2026-08-12):** these are dated working notes, retained as a snapshot of
> the 2026-06-07 analysis. Where they say "zero-dependency", read
> "minimal-dependency": since 0.8.0 the build pulls one pure-Go module,
> `golang.org/x/arch`, for x86/x64 disassembly. The intent the phrase encodes —
> no cgo, no native libraries, no runtime/system dependencies, and no heavy
> analysis frameworks such as RetDec/LLVM — is unchanged.

FlatScan baseline: pure-Go, minimal-dependency, **static-only** (never executes), signature/pattern + behavioral detection, format parsers (PE/ELF/Mach-O/APK/DEX/MSIX/ZIP), IOC extraction+triage, decoder pass, entropy, API-chain detection (7), packer fingerprint (8), rules engine (JSON+.rule), plugin engine, family classifier, similarity hashing (FlatHash/imphash/section), MITRE mapping, YARA/Sigma/STIX/PDF/HTML output, batch/watch/CI/web modes. **No ML, no dynamic analysis.**

---

## Paper 1 — Cross-architecture malware detection via Intermediate Representation (Greco & Ianni, JISA 2025)
**Idea:** Lift binaries (x86/ARM/MIPS) to **LLVM IR** using RetDec, then write **YARA-like rules against the IR** (architecture-independent). Custom high-level primitives: `ir_instruction("call mmap",[*,0x0,...])` (match call + arg values) and `loop(...)` (match behavior inside a loop). Also scans raw byte/data sections for strings/IPs. Resilient to instruction substitution, control-flow flattening, register reallocation, junk-code; NOT resilient to virtualization/JIT obfuscation. Lifting (RetDec) is the bottleneck → not real-time; aimed at border-gateway / forensic use.

**FlatScan status:** Partially ahead at the *symbol* level — FlatScan already matches behavior by imported-function/symbol names and strings, which is inherently cross-arch for the name layer (an ELF importing `mmap`/`fork` is detected regardless of x86/ARM/MIPS). It already scans raw data sections for IPs/strings, and detects API-hashing/dynamic-resolution.

**Gap:** FlatScan does NOT do instruction-semantics matching with concrete argument values, nor loop-structure detection. True IR lifting needs RetDec/LLVM = heavy external deps → violates zero-dependency design. 

**Verdict: Mostly out-of-scope (deps), partly already covered.** Cheap takeaway to *consider*: a lightweight "architecture-agnostic behavioral rule" layer that matches on imported symbol + nearby pushed constant args in ELF/PE relocation/PLT tables (no full lifter). Low priority.

---

## Paper 2 — Cost-aware RL-based MTD mutation for edge IoT vs DDoS (Javadpour et al., JISA 2025)
**Idea:** "CVbMA" — Moving Target Defense that mutates network nodes based jointly on vulnerability level + connection weight, driven by a cost-aware reinforcement-learning reward; neural ranking + model compression for scalability. Tested on Mininet + physical IoT testbed.
**Relevance to FlatScan:** None. This is a runtime *network defense* (dynamic attack-surface mutation against DDoS), not static file/malware analysis. Different problem domain entirely.
**Verdict: Out-of-scope. Nothing to implement.**

---

## Paper 3 — Dual-Channel Mamba zero-day malware detection (Alowaidi & Cansever, Applsci 16-05326, 2025)
**Idea:** Deep-learning (Mamba selective state-space model). Two encoders: a *semantic* channel over static artifacts (opcode/API tokens, PE structure) + a *behavioral* channel over dynamic API-call/syscall traces; cross-channel fusion; **prototype-guided zero-shot inference** classifies unseen families by embedding similarity to learned class "prototypes" (no retraining). ~96% acc, 88.9% zero-day rate.
**FlatScan status:** Static semantic side overlaps (FlatScan extracts imports/strings/capabilities). Dynamic channel N/A (FlatScan is static-only by design). No ML.
**Gap / transferable concept (non-ML):** **Nearest-family-prototype classification.** Build reference feature vectors per known family (capability set + import set + string-set/FlatHash signature) and classify an unknown sample by *similarity to the closest prototype*, returning "closest family + confidence" even when no exact rule fires. FlatScan already has similarity hashing + a heuristic family classifier; formalizing a prototype/nearest-neighbour layer (pure Go, Jaccard/cosine over feature sets) would add graceful zero-day-ish family guessing.
**Verdict: ML architecture out-of-scope. Worth considering: a lightweight prototype/nearest-neighbour family-similarity scorer. Medium value.**

---

## Paper 4 — Hand-crafted features → LLMs: Android malware detection paradigms (Taşkın & Doğru, Applsci 16-05600, 2026)
**Idea:** Comparative study (12k AndroZoo APKs) of classical ML (RandomForest ~0.975 F1) vs distilled Transformers (RoBERTa ~0.970, best latency) vs LLMs (Qwen-27B + LoRA ~0.982, best generalization + interpretability). Recommends tiered deployment: lightweight Transformer for screening, fine-tuned LLM for deep forensics. Classical features = Drebin set: permissions, API calls, intents, components, hardware features, URLs.
**FlatScan status: AHEAD / on-par on the static feature-engineering layer.** apk.go already extracts dangerous/special permissions, exported components, intents/actions (BOOT_COMPLETED, DEVICE_ADMIN), and rich API-pattern categories (SMS, contacts, location, mic/cam, accessibility, overlay, device-admin, package-install, Runtime.exec, network). That matches the classical "hand-crafted feature" paradigm the paper benchmarks.
**Gap:** No `uses-feature` hardware enumeration; no ML classifier on top of the features. ML/Transformer/LLM layers are out of scope (zero-dependency, no-training design).
**Verdict: FlatScan is even-to-ahead on classical Android static features. Only minor addition worth noting: enumerate `uses-feature` hardware tags. Otherwise nothing.**

---

## Paper 5 — Collaborative intrusion detection in resource-constrained IoT (JISA 2025)
**Idea:** Survey/evaluation of distributed/decentralised IDS (signature/rule/anomaly/ML) across low-power IoT to avoid single-point-of-failure of centralised IDS; edge + collaborative learning for scale + privacy.
**Relevance to FlatScan:** None. Network intrusion detection on live traffic across distributed nodes — different domain from static file scanning.
**Verdict: Out-of-scope. Nothing to implement.**

---

## Paper 6 — ConceptUML: multiphase unsupervised lateral-movement detection (Charles Sturt/CSIRO/UNSW, JISA 2025)
**Idea:** Fully unsupervised threat-hunting over system logs (Windows Event Logs, LMD-23). Phase1: Sentence-BERT embeddings + NMF concept extraction, fused with MITRE ATT&CK + CAPEC text. Phase2: HMM clustering + semantic-similarity scoring vs known techniques. Phase3: topic-modelling refinement. ~92.5% detection, no labels needed.
**Relevance to FlatScan:** Domain is log/SIEM threat hunting, not file scanning. The only transferable nugget: it enriches detections with **CAPEC** alongside MITRE ATT&CK. FlatScan already maps findings to MITRE TTPs but not CAPEC.
**Verdict: Out-of-scope overall. Tiny optional enrichment: add CAPEC IDs next to existing MITRE technique tags. Low priority.**

---

## Paper 7 — Conformal prediction for labelling/updating malware classifiers (Univ. León, JISA 2025)
**Idea:** Use conformal prediction (distribution-free uncertainty estimation) to produce statistically-reliable *pseudo-labels* to keep online ML malware classifiers updated under concept drift without ground truth. Honest negative result: improvements are inconsistent across datasets/models.
**Relevance to FlatScan:** None directly — FlatScan has no trainable ML model to update. Conceptual nugget only: calibrated *confidence / abstention* on a verdict. FlatScan emits a numeric risk score + verdict but no explicit confidence band.
**Verdict: Out-of-scope (ML lifecycle technique). Nothing to implement.**

---

## Paper 8 — DroidTTP: mapping Android apps to MITRE ATT&CK TTPs (Cochin/Padua/Pavia/Milan, JISA 2025)
**Idea:** Multi-label classification of *whole* Android apps to MITRE Tactics + Techniques. Features = Drebin-style (permissions, app components, intent actions, API calls). Best model: Label-Powerset XGBoost (Jaccard 0.989 tactic / 0.975 technique); fine-tuned LLaMa + RAG competitive. SHAP for explainability; adaptive per-label feature selection.
**FlatScan status: conceptually AHEAD** — apk.go already attaches a MITRE tactic + technique to *each* Android finding and reports aggregate a MITRE matrix, rule-based, no training needed. DroidTTP's contribution is the ML/LLM mapping engine + curated feature→TTP dataset.
**Gap (dependency-free, concrete — verified):** FlatScan already embeds canonical T-IDs in chains.go/dotnet.go (39 refs, e.g. `Process Injection (T1055)`), BUT apk.go's Android findings use *descriptive names only* ("SMS Collection", "Device Administrator Abuse", "Input Capture / Accessibility Abuse") with no IDs. So the gap is **inconsistency**: add canonical **MITRE Mobile ATT&CK** IDs to Android findings (e.g. T1582 SMS Control, T1417 Input Capture, T1626 Abuse Elevation Control, T1517? Access Notifications) so Sigma/STIX/MITRE-matrix outputs are machine-correlatable across all modules. Whole-sample "TTP coverage profile" for Android is already largely present.
**Verdict: ML engine out-of-scope; FlatScan already maps features→TTPs by rule. Worthwhile small win: tag Android (and other) findings with canonical MITRE technique IDs, not just names. Medium value.**

---

## Paper 9 — Malware-as-image detection with VGG-16/19 deep learning (Electronics 11-03665, 2022)
**Idea:** Convert raw malware bytes → 224×224×3 images, then a two-stage VGG CNN: stage1 malware/benign, stage2 type (Locker, etc.). Standard "malware visualization + CNN" paradigm. Dataset 8970 mal / 1000 benign.
**Relevance to FlatScan:** Detection method (CNN over byte-images) is ML — out of scope. Older (2022), fairly conventional.
**Transferable non-ML nugget:** the *byteplot / entropy-bitmap visualization* itself (independent of the CNN). FlatScan already computes Shannon entropy + high-entropy regions; rendering a grayscale byteplot or entropy-strip image into the HTML report would give analysts a quick visual fingerprint (spot packed regions, appended data, embedded PE) with zero new deps (Go `image/png` is stdlib).
**Verdict: ML detector out-of-scope. Optional cosmetic win: byteplot/entropy-map image in HTML report. Low-medium value.**

---

## Paper 10 — GuardFS: file-system-based ransomware detection + mitigation (Univ. Zurich / armasuisse, JISA 2025)
**Idea:** Bespoke **overlay (FUSE) file system** that extracts data before files are accessed; ML models drive 3 reactive defenses — obfuscate / delay / track file access — to *prevent* (not just alert) ransomware damage on Linux. Reduces but can't fully prevent data loss; trade-off vs performance/usability.
**Relevance to FlatScan:** None as a detection method. This is a *runtime kernel/FS agent* observing live I/O (write entropy, access sequences) — things a static scanner can't see. FlatScan's `watch.go` monitors a dir and statically scans new files on arrival, which is a far lighter, different mechanism (no interception/mitigation).
**Verdict: Out-of-scope (runtime FS interception conflicts with static design). Nothing to implement.**

---

## Paper 11 — Integrated (static+dynamic) analysis of malware (Andronache et al., JCP 5-00098, 2025)
**Idea:** Case-study methodology combining static (file structure, strings, code signatures, entropy, imports/exports, sections, YARA) + dynamic sandbox (process creation, network comms, FS changes via RegShot/Wireshark/ProcMon/FakeNet). Goal: better profiling by fusing structural + behavioral indicators.
**FlatScan status: AHEAD on the static half.** Their static toolchain = VirusTotal + Strings + PEStudio + YARA, done manually. FlatScan does *all* of that (type/arch/metadata, entropy, imports/exports, API-capability inference, sections, strings) in ONE pass and auto-generates the YARA — plus Sigma/STIX/PDF the paper doesn't.
**Gap / in-scope idea:** the paper's value is the static+dynamic *fusion*. FlatScan stays static (never executes) — but it could **ingest an external sandbox/dynamic report** (CAPE/Cuckoo/Triage JSON) and overlay runtime IOCs/behaviors onto its static profile. This keeps the "never execute" guarantee (just parses JSON) while adding hybrid context. No such importer exists today.
**Verdict: FlatScan already exceeds the static toolchain. Genuine in-scope add: optional dynamic-report (sandbox JSON) importer to enrich findings. Medium-high value.**

---

## Paper 12 — ML static ransomware detection via PE header features + SHAP (Barnes & Ghafarian, JCP 6-00058, 2025)  ⭐ BEST CONCRETE WIN
**Idea:** Train RF/SVM/XGBoost on *static PE header features* for 3 tasks (ransomware vs benign, malware vs benign, ransomware vs other-malware). XGBoost best. **SHAP interpretation** ranks which header fields are most discriminative.
**Key empirical result:** `DllCharacteristics` is the **#1 most discriminative PE-header feature** (mean |SHAP| 2.085) — *lower* values (i.e., fewer security mitigations like ASLR/DYNAMIC_BASE, DEP/NX_COMPAT, CFG/GUARD_CF) push the prediction toward ransomware/malicious. Architecture (Machine x86/x64) is #2. (Also notes discrimination collapses for ransomware-vs-other-malware — structural features can't separate malware families, only malware-vs-benign.)
**FlatScan status (VERIFIED gap):** formats.go parses `OptionalHeader.Subsystem` + section characteristics but **does NOT read or score `DllCharacteristics`** — the single most predictive static field per this study. Go stdlib `debug/pe` exposes `OptionalHeader32/64.DllCharacteristics uint16` directly — zero new deps.
**Concrete implementation:** (1) decode DllCharacteristics bitmask into readable flags (DYNAMIC_BASE/ASLR, NX_COMPAT/DEP, GUARD_CF/CFG, HIGH_ENTROPY_VA, FORCE_INTEGRITY, NO_SEH); (2) raise a mild suspicion finding when a PE *lacks* expected modern mitigations (esp. no ASLR + no DEP + no CFG), since that pattern correlates with malicious binaries. Also surface it in PE report section.
**Verdict: ⭐ Strongest, research-backed, dependency-free win. Implement DllCharacteristics parsing + "missing security mitigations" heuristic. High value, low effort.**

---

## Paper 13 — LPASS: Linear Probes for compressed-LLM vulnerability detection (Inria/IP Paris, JISA 2025)
**Idea:** Use Linear Probes to predict a compressed LLM's post-fine-tune accuracy early + pick layer-pruning cut-offs. Applied to BERT/Gemma for detecting 12 of MITRE Top-25 vulnerabilities in 480k C/C++ *source* samples. 86.9% multi-class accuracy; big compute savings.
**Relevance to FlatScan:** None. Source-code vulnerability detection + LLM-compression methodology. FlatScan analyzes *compiled binaries*, not source, and uses no LLMs.
**Verdict: Out-of-scope. Nothing to implement.**

---

## Paper 14 — LLMs for detecting Algorithmically Generated Domains / DGA (Pelayo-Benedet et al., JISA 2025)
**Idea:** Evaluate 9 commercial LLMs (zero-shot + 10-shot) to classify malicious AGDs/DGA domains without training; 77–89% accuracy; bigger models distinguish DGA families (esp. hash-based schemes).
**FlatScan status (VERIFIED gap):** ioc.go extracts domains via regex but performs **no DGA-likeness analysis** at all. 
**Transferable non-LLM concept:** classic, dependency-free **DGA heuristic scoring** on each extracted domain — Shannon entropy of the SLD, consonant-run length, digit/hyphen ratio, vowel ratio, and bigram/trigram improbability vs English frequency table. Flag high-randomness domains as likely-C2 (DGA) indicators and feed into IOC triage + scoring. This is exactly how non-ML DGA detectors (e.g., classic entropy/n-gram methods) work — pure Go, no model.
**Verdict: LLM method out-of-scope, but the underlying need is real. Add a lightweight DGA-likeness scorer for extracted domains. Medium value, low effort.**

---

## Paper 15 — Practitioner perspectives on privacy-harm categories for privacy risk assessment (JISA 2025)
**Idea:** Empirical interview study on whether privacy-harm taxonomies help in PIAs/DPIAs (GDPR). Privacy engineering / governance.
**Relevance to FlatScan:** None. Privacy risk assessment methodology, not malware detection.
**Verdict: Out-of-scope. Nothing to implement.**

---

## Papers 16–22 — Clearly out-of-scope (classified by title/topic; not malware detection)
- **Editorial-Board** — journal front-matter, 1 page. Not a paper.
- **Efficient NTT/INTT processor for FALCON** — post-quantum signature (lattice crypto) hardware accelerator. Cryptography.
- **Enforcing data access control and privacy** — access-control / privacy enforcement. Not malware.
- **Improving the security of asymmetric secret sharing** — secret-sharing cryptography.
- **Quo Vadis CKKS** — CKKS fully-homomorphic-encryption realization comparison. Cryptography.
- **Secure order-based voting using distributed [ledger]** — e-voting protocol. Cryptography/governance.
- **Security implications of user non-compliance behaviour** — human-factors / security behaviour study.
**Verdict: All out-of-scope for a static malware scanner. Nothing to implement.**

---

# SUMMARY — what to actually do

**FlatScan is at or ahead of the research on its core static-analysis turf.** Most ML/DL/LLM papers describe *classifier* technology layered on feature sets FlatScan already extracts; FlatScan's deliberate design (pure-Go, zero-dependency, never-execute, no training) puts those engines out of scope. Of 22 PDFs, 15 are off-domain (crypto/voting/privacy/network-IDS/runtime-FS) and ~7 touch FlatScan's domain.

**Concrete, dependency-free, research-backed upgrades (ranked):**
1. ⭐ **PE `DllCharacteristics` parsing + "missing security mitigations" heuristic** (Paper 12). #1 most discriminative static PE feature per SHAP. Field is in Go stdlib `debug/pe`. HIGH value / LOW effort.
2. **DGA-likeness scorer for extracted domains** (Paper 14) — entropy + n-gram improbability + consonant/digit ratios. MEDIUM / LOW.
3. **Sandbox/dynamic-report (CAPE/Cuckoo/Triage JSON) importer** to add hybrid behavioral context while staying static (Paper 11). MEDIUM-HIGH / MEDIUM.
4. **Canonical MITRE technique IDs on Android (+ all) findings** incl. MITRE Mobile IDs (Paper 8) — consistency win. MEDIUM / LOW.
5. **Nearest-family-prototype similarity scorer** — "closest known family + confidence" for samples that fire no exact rule (Paper 3). MEDIUM / MEDIUM.
6. **`uses-feature` hardware enumeration in APK parsing** (Paper 4). LOW / LOW.
7. **Byteplot / entropy-map image in HTML report** (Paper 9) — analyst visual fingerprint, stdlib `image/png`. LOW-MEDIUM / LOW.
8. *(optional)* CAPEC IDs beside MITRE tags (Paper 6). LOW / LOW.

**Out of scope by design (won't implement):** ML/DL classifiers (Mamba/VGG/XGBoost/Transformers), LLM-based detection, IR lifting via RetDec/LLVM, runtime FUSE/overlay mitigation, network IDS, MTD, conformal online-learning.
