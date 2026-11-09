# Strategic Review Checklist

**Purpose:** Guide the strategic review process every 8 completed iterations.
**When to use:** At iterations 8, 16, 24, 32, etc.
**Time required:** 30–45 minutes
**Last Review:** N/A (next due after `[iter-8]`)

---

## Part 1: Big Picture Direction (10 minutes)

1. **Are we solving the right problem?**
   - [ ] Does `chaosreader2026` still deliver "one capture in → one browsable, safe, static artifact directory out"?
   - [ ] Are we preserving Chaosreader's UX clarity rather than rebuilding a noisy CLI packet dumper?
   - [ ] Decision: Continue current direction / Pivot / Refocus
2. **Patterns from the last 8 iterations:**
   - [ ] Which carvers/features delivered the highest investigative signal?
   - [ ] Where did scope creep or edge-case complexity bite?
3. **Hill-climbing check:**
   - [ ] Are we climbing the right hill (real 2026 traffic utility) vs. over-polishing rare legacy protocols?

---

## Part 2: Backlog Health Check (10 minutes)

1. **Priority 1 Items:**
   - [ ] Still high-value and scoped to 30–45 minutes?
   - [ ] Any item stuck 5+ iterations? (Split, demote, or delete.)
2. **Priority 2–4 & Ideas Inbox:**
   - [ ] Sort **Ideas Inbox** items into Priority 1–4 or discard.
   - [ ] Promote next 3–5 `[FOCUS]` items into Priority 1.
3. **Completed Archive:**
   - [ ] Verify all `[iter-N]` commits from the cycle are recorded under **Completed**.

---

## Part 3: Code, Test & Security Health (10 minutes)

1. **TDD & Test Health:**
   - [ ] `cargo test` green with zero flaky tests?
   - [ ] `cargo clippy --all-targets -- -D warnings` clean?
   - [ ] Are tests exercising real synthetic wire bytes rather than brittle mocks?
2. **Analyst & Public-Repo Safety:**
   - [ ] `./scripts/check-public-safety.sh --all` passing?
   - [ ] All untrusted packet strings strictly escaped in HTML/JSON/replay outputs (zero XSS, zero remote image beacons, zero raw PTY escape execution)?
   - [ ] Malformed/truncated packet slices handled without `unwrap()` panics?
3. **Architecture & Debt:**
   - [ ] Any repeated byte-parsing or report-rendering patterns ready to extract?

---

## Part 4: Process Reflection (5 minutes)

1. Were iterations kept to one task and 30–60 minutes?
2. Was every production change preceded by a watched failing test (`RED → GREEN → REFACTOR`)?
3. Did the Gilfoyle hypothesis ledger resolve ambiguities cleanly when packet formats surprised us?

---

## Part 5: Next 8 Iterations Plan (10 minutes)

- **Primary Focus Area:** Features / Protocol Coverage / Security & Robustness / Performance / UX
- **Top 3–5 `[FOCUS]` items marked in `BACKLOG.md`:**
  1. TBD
  2. TBD
  3. TBD
