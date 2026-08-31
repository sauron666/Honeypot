# A Hypervisor-Agnostic Ransomware Tarpit for Deception Networks

*Working draft — MIRAGE deception platform. Language: English (the project's
tutorials are in Bulgarian; this paper is drafted in English for publication and
can be translated).*

## Abstract

Agentless virtual-machine introspection (VMI) such as DRAKVUF gives a deception
platform deep, tamper-proof visibility into a decoy, but it is bound to a
narrow hardware and hypervisor niche: Xen on a CPU exposing the VMFUNC/`#VE`
altp2m primitives. Production estates predominantly run KVM/QEMU, VMware ESXi
and Hyper-V, where this visibility is unavailable. We present a
**hypervisor-agnostic ransomware trap**: a userspace (FUSE) decoy file share
whose every operation is scored by an online ransomware detector and delayed by
an escalating **tarpit** before it reaches the backing store. The design needs
no in-guest agent and no VMI, so it holds identically on any platform that can
mount a network share. We formalise the detector's signals, describe the tarpit
throttle, and define a reproducible measurement of the defence in terms of
**detection latency** (operations until confirmation) and **files spared**. On a
deterministic cryptor-simulation harness the trap confirms ransomware after 2 of
30 file operations in a full-share sweep, i.e. before the attacker reaches the
majority of files, while imposing zero delay on ordinary browsing.

## 1. Introduction

Ransomware remains the highest-impact commodity threat to enterprise networks.
Deception (honeypots/honeynets) is attractive against it because a decoy has no
legitimate users: **any** writer on a decoy share is, by construction, hostile,
which removes the false-positive problem that plagues host-based ransomware
detection on production endpoints.

The strongest deception visibility today is agentless VMI. MIRAGE integrates
DRAKVUF on Xen and has validated full introspection on Windows Server 2025
(regmon/filetracer/procmon). But DRAKVUF requires altp2m (VMFUNC), which exists
only on recent Intel parts (e.g. Ice Lake) and only under Xen. This excludes the
hypervisors most customers actually run. A deception product that can only
protect Xen estates is not deployable at scale.

**Contribution.** We show that for the specific, high-value case of ransomware,
one does not need VMI at all. A userspace decoy filesystem intercepts the file
operations that *define* ransomware (high-entropy overwrites, magic-byte
destruction, mass extension changes, canary access), scores them online, and —
crucially — **throttles the attacker on their own thread** by delaying each
operation in proportion to suspicion. The same code runs unchanged on KVM,
VMware, Hyper-V or a re-exported SMB/NFS share to a real endpoint.

## 2. Threat model

We assume an attacker who has obtained code execution on a host with access to a
network file share we control, or who has compromised a full-OS decoy that
mounts our share. The attacker runs a cryptor that enumerates the share and
encrypts files, optionally renaming them with a marker extension and dropping a
ransom note. We do **not** assume the attacker inspects the filesystem
implementation; we discuss detection of the trap itself in §7. We are not
defending production data — the share is bait — so aggressive throttling that
would be unacceptable on a real fileserver is free here.

## 3. Design

### 3.1 Architecture

MIRAGE serves the trap as a FUSE filesystem seeded with a plausible corporate
tree (`Finance/`, `HR/`, `Backups/`) containing decoy documents and **canary**
files. A decoy on any hypervisor mounts the share (or it is re-exported over
SMB/NFS to a real endpoint). Every VFS operation the kernel forwards over
`/dev/fuse` is handled by MIRAGE in userspace, which:

1. records the operation as a typed event (read/write/create/rename/delete);
2. feeds it to the ransomware detector, which returns any new *findings*;
3. computes a **tarpit delay** from the current suspicion score and sleeps the
   handling thread for that long before returning to the kernel — the syscall
   the attacker issued does not complete until the delay elapses;
4. on the first *confirmation*, fires a one-shot callback that snapshots the
   decoy (preserving the encrypted state on the hypervisor for forensics) and
   emits a critical, ATT&CK T1486-tagged event into the tamper-evident evidence
   chain.

The detector and all judgement live in a portable core with no kernel
dependency, exercised by unit tests on every platform; the FUSE binding is a
thin Linux-only translation layer.

### 3.2 Detection signals

The detector accumulates a score across the operations of one session; each
signal contributes once (a thousand encrypted writes are one detection, not a
thousand). Signals and default weights:

| Signal | Weight | Rationale |
|---|---|---|
| high-entropy-write | 25 | Shannon entropy of the written sample ≳ 7.5 bits/byte, the fingerprint of ciphertext (and compressed data — separated by the next two signals). |
| file-type-destroyed | 25 | A file whose magic bytes identified a known type (docx, xlsx, pdf…) is overwritten with content of unknown type: in-place encryption. |
| mass-extension-change | 25 | Renames appending a uniform new extension (`.locked`, `.crypt`). |
| write-velocity | 15 | More than *N* file operations within a sliding window: a human does not rewrite a share in seconds. |
| canary-touched | 25 | First access to a bait file no legitimate process has reason to open. |
| ransom-note | 30 | A written file matches ransom-note heuristics (payment/onion/contact patterns). |

Confirmation fires when the cumulative score reaches a threshold (default 70).
Note that entropy + extension + velocity alone total 65, deliberately *below*
the threshold: encrypting brand-new files a user might plausibly create is not
enough on its own; in-place destruction of an existing typed file, or a canary
touch, tips it over. This is a design choice that trades a marginally later
confirmation for a lower false-positive posture even in the all-hostile setting.

### 3.3 The tarpit

The delay imposed on operation *i* is a function of the current score *s*:

> delay(s) = min( TarpitMax, (min(s/C, 2))² · TarpitMax / 4 )

where *C* is the confirmation threshold and `TarpitMax` the cap (default 8 s).
The delay is **quadratic** in suspicion: negligible while unsure (so a
legitimate spot-check of one file is instant), then rising steeply once the
score approaches and exceeds *C*, so a confirmed cryptor is throttled to one
operation every several seconds. Because the delay is imposed synchronously on
the FUSE handler — the attacker's own thread — it directly reduces the
attacker's encryption throughput. This is the mechanism by which detection
translates into **files spared**: every second the cryptor is stalled is a
second in which files it has not yet reached remain intact, and the
confirmation-triggered snapshot captures the rest.

## 4. Methodology

We define two reproducible metrics, both dimensionless or in operation counts so
they do not depend on machine speed:

- **Detection latency** `confirm_ops`: the number of file operations processed
  before confirmation. Lower is better.
- **Files spared (proxy)**: `1 − confirm_ops / total_ops` over a full-share
  sweep, the fraction of the sweep still unreached at confirmation.

We drive the portable detector core with a synthetic cryptor that, per target
file, issues read → high-entropy overwrite → rename-to-`.locked`, over the
seeded tree, using a controllable clock so results are independent of wall-clock
speed and fully deterministic. The harness is the package's test suite
(`internal/fusetrap`), so every result below is regenerated on every CI run.

For **live** validation on real hypervisors, the same trap is mounted (Linux
host, `/dev/fuse`) and exported to a decoy; a ransomware sample (or a benign
encryptor such as an AES loop over the share) is detonated inside the decoy. The
platform records the same metrics from real kernel-driven FUSE operations. Live
runs are hypervisor-independent by construction; we report the simulation
numbers here and note live validation as ongoing (§8), mirroring the project's
honesty convention of not claiming unvalidated results.

## 5. Results (simulation harness)

On the seeded tree (12 files across three directories, 3 of them canaries), a
full encrypting sweep is 30–36 operations. The trap:

- raises its **first signal on operation 1** (a canary or the first
  high-entropy overwrite);
- **confirms on operation 2** in the full-sweep test — before the cryptor has
  finished the second file, sparing ~90% of the share;
- imposes **zero** tarpit on a legitimate browsing sequence (reads of existing
  low-entropy documents produce no signal, hence no delay);
- escalates the per-operation tarpit monotonically with suspicion, reaching the
  multi-second regime once confirmed.

These are asserted as invariants by the test suite (`TestReportableMetrics`,
`TestTarpitGrowsWithSuspicion`, `TestBrowsingTheShareIsInstant`,
`TestRansomwareIsConfirmedAndSnapshotFires`), so regressions in the defence
surface as test failures rather than silent weakening.

## 6. Integration and evidence

Findings enter MIRAGE's append-only, hash-chained evidence store on the same
path as every other event, so a ransomware engagement is legally admissible:
the chain can be sealed (ed25519) and RFC 3161 timestamped and verified by a
third party. Confirmation additionally triggers a hypervisor snapshot of the
decoy, capturing the encrypted disk state as forensic evidence.

## 7. Limitations and evasion

- **Trap detection.** A careful attacker could fingerprint a FUSE mount
  (filesystem type, latency signature) and avoid it. The tarpit's very latency
  is a potential tell; the quadratic curve keeps early latency low to delay this
  realisation, but a patient adversary who writes one file, notices the delay
  and stops is detected (that write is scored) but not throttled further. The
  defence's value is highest against automated, indiscriminate cryptors, which
  are the common case.
- **New-file-only cryptors.** Malware that writes ciphertext to *new* files and
  deletes originals avoids the magic-loss signal; it is still caught by entropy
  + velocity + canary, but confirmation may come a few operations later.
- **Sub-threshold trickle.** An attacker encrypting extremely slowly stays under
  the velocity signal; entropy and canary still apply, and the engagement is
  still recorded, but the tarpit stays mild. This is an inherent detection/FP
  trade-off, tunable per deployment.
- **Simulation vs. live.** Numbers here are from the deterministic harness;
  live kernel behaviour (caching, write coalescing) will shift absolute op
  counts. The metrics are defined to be robust to this, but live figures are
  reported separately once collected.

## 8. Future work

- Live measurement across KVM/Proxmox, VMware and Hyper-V with real ransomware
  families; report per-family detection latency and files-spared.
- Adaptive thresholds learned from the share's own (zero) baseline activity.
- Coupling the tarpit with fabric-level containment: on confirmation, move the
  decoy's segment to a sinkhole VLAN via the NAC driver.
- A companion signal from disk-image entropy sampling for VMs whose disk is a
  host file, catching cryptors that never touch the share.

## 9. Related work

VMI-based malware analysis (DRAKVUF, LibVMI); ransomware detection by file-system
behaviour and entropy (CryptoDrop, ShieldFS, Redemption); decoy/canary files
(honeyfiles) and network deception. Our contribution is not a new detector but
the combination of an all-hostile decoy share, a synchronous per-operation
tarpit as an active throttle, and hypervisor independence, delivered as a
production deception feature with tamper-evident evidence.

## 10. Reproducibility

Everything is in `internal/fusetrap/` (portable core + tests) and
`internal/ransomware/` (detector). Run:

```bash
GOTOOLCHAIN=local go test -v -run 'Metrics|Tarpit|Confirmed|Browsing' ./internal/fusetrap/
```

The test log lines prefixed `METRICS` and `confirmed after …` are the numbers
cited in §5.
