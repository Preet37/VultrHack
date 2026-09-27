# Cerberus console — build backlog (from live feedback)

## In progress (this pass)
- [x] Diffs readable (card 2px-collapse fixed)
- [x] Apply-all + per-patch Apply/Copy
- [x] Containment crash dialog on kill
- [x] Remove stepper; Act 1 reads as system reasoning
- [ ] Agent-to-agent comms feed (rail) + glow on the two talking agents
- [ ] Results / benchmark dashboard (exploits, endpoints, LOC rewritten, cert rate, scan time)
- [ ] Kali-style backdrop for the instance desktop using the Cerberus logo (not white/plain)

## Next pass — the machine-in-a-machine shell (headline)
- [ ] On detonate, DON'T replace the launcher desktop. Keep the main Cerberus VM
      desktop visible; open the disposable instance as a WINDOW ON it (nested VM).
      You can still see the main desktop around/behind the running box. (imgs #40/#41)
- [ ] Inner disposable VM gets its own Kali-style desktop (Cerberus logo watermark,
      geometric backdrop) so it reads as a different machine. (img #42)

## Next — human-in-the-loop remediation
- [ ] Each suggested patch: Apply AND Decline.
- [ ] On Apply → actually mark applied, then SPIN A NEW disposable VM and re-run the
      exact same find/prove flow to confirm the applied fix holds (user-driven re-verify loop).
- [ ] On Decline → leave the vuln open, note it.

## Next — real repo intake
- [ ] "Paste a GitHub URL" → actually clone (shallow) + show git-clone/download progress
      (Receiving objects: %). Currently local seeded targets only, so the download
      concept isn't visible. Make the clone/download step real for a pasted repo.

## Honesty notes to preserve
- Live Vultr gVisor host = issue #16 (Sasha). Keep "runner: local-subprocess (tier-1) ·
  live Vultr gVisor host pending #16" visible.
- seeded_flask has planted bugs — it's a known-answer test fixture; the method
  (environmental canaries in the sandbox, not the customer's repo) is what generalizes.
- Kill is currently a containment POLICY (proven breach ⇒ destroy), not an LLM judging
  in the moment. Don't overclaim "reasoning" beyond that until the reasoning layer exists.
