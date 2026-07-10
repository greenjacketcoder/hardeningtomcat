# Why the Engine Is Built This Way

HardeningTomcat exists because the reference implementation it was inspired by
(HardeningKitty) shows what happens to audit tools that grow organically: a
21-branch if/elseif ladder deciding how to check each finding, a *separate*
duplicated ladder for applying, and CSV lists whose overloaded columns mean
different things per method. This document explains the design that replaces
that — and what each choice trades away.

## The problem

Three failure modes drive the whole architecture:

1. **Audit/apply drift.** When checking and fixing are two code paths, they
   disagree eventually — the audit says a setting is wrong, the fix writes a
   subtly different value, and the next audit still fails (or worse, passes
   when it shouldn't).
2. **False confidence.** A security tool that reports "Pass" for a setting it
   couldn't actually read is worse than no tool. Unreadable must never look
   compliant.
3. **A bricked machine with no forensics.** Hardening can disable boot paths,
   logons, and remote access. When that happens you need to know *which
   setting* did it and *what the value was before*.

## The approach

```
finding list (typed JSON)          Handlers/*.ps1 (one per method)
        |                                   |
        v                                   v
  [validate fail-fast] --> [integrity check] --> [prefetch once per method]
        |
        v
  ONE loop per finding:  Test (observe) -> engine compares -> Apply (mutate, Strike only)
        |                                        |
        v                                        v
  results + score                 backup dir + undo-journal.jsonl
```

- **Handler registry, not a ladder.** Each check method is one file in
  `Handlers/` returning `@{ Name; Test; Apply; Prefetch }`. The engine
  discovers them at load; adding a method touches zero engine code. Handlers
  *observe* in Test and *mutate* in Apply — the engine owns all operator
  comparison, so a handler can't invent its own pass/fail semantics.
  *(Trade-off: scriptblock hashtables instead of classes — the price of
  PowerShell 5.1 compatibility.)*
- **One loop drives audit AND apply.** Strike is Recon plus an Apply step on
  failed findings — the same observation, the same comparison. Drift between
  "what we audit" and "what we fix" is structurally impossible.
- **Prefetch batching.** `auditpol` and `secedit` exports take seconds per
  spawn. Each handler may run one Prefetch per run, caching parsed output;
  every finding is then an in-memory lookup. Symmetrically, `FlushApply` lets
  a handler batch its writes into one operation (one `secedit /configure`,
  not dozens — repeated calls exhaust the Security Configuration Engine).
  *(Trade-off: prefetched state can go stale mid-run; acceptable because a run
  takes seconds and audits a point in time.)*
- **Honest failure.** Anything unevaluable is **Skipped** — no handler, no
  elevation, missing binary, test error, manual-verification findings. The
  numeric operators refuse empty observations rather than coercing to 0
  (in PS 5.1, `[int64]''` silently returns 0 — which would grade an
  *unconfigured* control as *compliant*). Apply failures are surfaced in red
  in the summary, never only in the log.
- **Layered integrity, honestly labeled.** Structural validation (fail-fast,
  all problems at once) → SHA256 manifest (Strike refuses unlisted lists) →
  signed catalog via `Sign-Module.ps1` (actual tamper resistance) →
  `-RequireSignedHandlers` (Authenticode on the code itself). The tool tells
  you which layer you're missing: an unsigned manifest only detects
  *accidental corruption*, and Strike says so at run time. The list file is
  read once and hashed+parsed from the same buffer, closing the
  check-then-use race.
- **Forensics-first writes.** `-Log` flushes per line (the last line names the
  setting that hung the machine); every apply logs its exact target *before*
  writing; and the undo journal records each finding's pre-change value
  *before* each apply — see
  [How to run a safe Strike](howto-safe-strike.md#undo-a-strike-with-the-journal).

## Trade-offs accepted

- **English-only analysis.** Value comparison assumes English system output;
  localized systems may misreport. Called out in the README rather than
  half-supported.
- **Point-in-time audit.** No agent, no drift monitoring — it's a scan tool,
  by design. Re-run Recon when you want fresh truth.
- **Manifest is not signing.** Keeping `manifest.sha256` as plain text makes
  list regeneration friction-free during development; the signed catalog is
  opt-in for production use.
- **Skipped findings lower coverage silently-ish.** A non-elevated run can
  skip hundreds of findings. Mitigated by the up-front warning with exact
  counts — but the score only grades what was evaluated.

## Alternatives considered

- **Fork HardeningKitty** — rejected; the CSV format and dual-ladder
  architecture are the problems, not incidental details (see README: "inspired
  by, not a fork").
- **Depend on HardeningKitty's translated lists forever** — rejected; the
  `Importers/` pipeline reads Microsoft's own SCT artifacts so new baselines
  work without a third party in the chain (see
  [Importers/README.md](../Importers/README.md)).
- **PowerShell classes for handlers** — rejected for 5.1 compatibility;
  scriptblock hashtables run identically on 5.1 and 7+.

## Related

- [Handler contract](../Handlers/_CONTRACT.md) — the exact shape this design enforces
- [Invoke-HardeningTomcat reference](reference-invoke-hardeningtomcat.md) — the gates and operators
- [Finding list format](reference-finding-list-format.md) — the typed JSON that feeds it
