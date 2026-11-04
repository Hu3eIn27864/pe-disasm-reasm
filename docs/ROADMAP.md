# PE Disassembler/Reassembler Roadmap

Estimates assume one developer at 6–10 focused hours per week. This is a focused experimental tool, not yet a general-purpose PE rewriting framework.

## M0 — Reproducibility (1 week)
- [ ] Remove machine-specific paths and undocumented generated artifacts from examples.
- [ ] Declare dependencies and supported Python versions.
- [ ] Add synthetic PE fixtures and smoke tests.
**Exit:** clean checkout runs documented commands.

## M1 — PE parsing and section model (2–4 weeks)
- [ ] Validate DOS/NT headers and PE32 constraints.
- [ ] Handle section alignment and raw/virtual size differences.
- [ ] Reject malformed ranges safely.
**Exit:** tests cover valid and malformed inputs.

## M2 — Disassembly listing format (3–5 weeks)
- [ ] Preserve address, bytes, instruction/data classification and section identity.
- [ ] Handle code/data boundaries explicitly.
- [ ] Report unsupported instructions and gaps.
**Exit:** deterministic listings on synthetic fixtures.

## M3 — Reassembly and round-trip tests (4–8 weeks)
- [ ] Rebuild sections with correct alignment and headers.
- [ ] Preserve imports, relocations and overlays only where implemented and tested.
- [ ] Add byte-level diff reports.
**Exit:** documented fixture-specific round-trip results.

## M4 — Release hardening (2–3 weeks)
- [ ] Add CLI help examples and limitations.
- [ ] Add CI and a small regression corpus.
- [ ] Document legal input handling and safe test practices.
**Exit:** reproducible experimental release.

## Schedule

| Period | Deliverable |
|---|---|
| Week 1 | M0 |
| Weeks 2–5 | M1 |
| Weeks 6–10 | M2 |
| Months 3–4 | M3 |
| Month 5 | M4 |

Do not claim general-purpose or byte-identical reconstruction until the regression corpus demonstrates it across explicitly listed cases.
