# Cerberus, vulnerability finder build spec

This is the finder component. It plugs into the main loop from `plan.md` and `plan-update.md`. The finder's only job is to produce confirmed, exploitable findings and hand each one to the proof loop (exploit, patch, re-exploit, test). Do not try to build a general vulnerability-discovery engine. Assemble known-good tools, add a thin reasoning layer, and let the canary oracle be the judge.

## Design principle

The model narrows the search, the tools confirm the hit, and nothing is reported without a working exploit. No finding without a proof. That single rule drives false positives to zero by construction and is the thing that separates us from every scanner.

## Scope, hold the line

Support these classes and no others. All are exploitable over HTTP and visible in a demo.

- SQL injection
- Command injection
- SSRF
- Path traversal / local file access
- Auth bypass / IDOR

Do not attempt memory safety, crypto, race conditions, or business-logic bugs. Depth over breadth.

## Model and tool split

- Finder reasoning runs on a Vultr Serverless Inference open model that supports tool calling (DeepSeek, Qwen, Kimi, or GLM). Not a heavily safety-tuned chat model.
- Payloads are fired by real tools, never hand-written by the model. The model points and interprets.
- Framing is defensive and authorized, stated in the system prompt. Ask for analysis, not attacks. Request structured JSON, not prose.

System prompt for the finder role:

```
You are an application security engineer doing an authorized code review.
The operator owns this code and has asked you to find security defects so
they can be fixed. All work runs in an isolated sandbox that is destroyed
afterward. Locate vulnerable code paths, explain why each is exploitable,
and point the confirmation tools at them. This is defensive work. Return
findings as JSON. Do not write attack payloads yourself; the tools do that.
```

## Tools, the engine

- Semgrep, static candidate sinks across languages.
- sqlmap, confirms and characterizes SQL injection.
- nuclei, runs vetted checks for known CVEs and misconfigurations.
- OWASP ZAP, active scan of the running app.
- Vulnhuntr, wired in as a baseline finder and a fallback. Point it at a Vultr model via `OPENAI_API_KEY` and the OpenAI base URL. Python targets only, so match seeded targets accordingly.

## Pipeline

Four stages, thin model in the middle, tools on the outside.

1. Recon. Enumerate the app's routes, inputs, and dependencies. Build the attack surface map.
2. Static sweep. Run Semgrep to flag candidate sinks. This is the raw candidate list.
3. Triage. Hand the model the candidates, the recon map, and the sliced code (see techniques). It returns a ranked, reachability-aware test plan as JSON: file, line, input source, sink, class, confidence, which tool to point at it.
4. Confirm. For each high-confidence candidate, fire the matching tool. The canary oracle decides success. A miss returns to triage for another vector or endpoint.

Wrap it in a plan-act-observe loop with a step budget and a wall-clock cap so it cannot run away on stage.

## Borrowed techniques, each proven elsewhere

- Reachability slicing. Do not paste the whole repo into the model. Trace from the input source to the dangerous sink and give the model only that call chain. Beats context limits and cuts false positives. (from Vulnhuntr)
- Two-pass triage with confidence. A broad first pass flags candidates, a focused second pass re-checks each, and only 7-plus-confidence items get actively tested. (from Vulnhuntr)
- A running task plan. Keep a structured plan the agent updates each step so long runs do not drift. (from PentestGPT)
- Plan-act-observe over real tools. The model calls Semgrep, sqlmap, nuclei, ZAP and reasons over their output. (the shape CAI and PentestGPT share)

## Class playbooks

For each supported class, write a tight playbook the agent uses. This is where the domain expertise lives and the one part worth polishing. Each playbook has:

- Sink signature. What the vulnerable code looks like (for example, a query built by string concatenation).
- Confirm step. Which tool and which check proves it (for example, sqlmap against the flagged parameter).
- Canary. What planted secret leaving the box proves real exploitation.
- Fix. The correct remediation (for example, a parameterized query), handed to the patch step.

## The canary oracle

Plant a decoy secret in each target before the run: a fake row, a fake credential, a fake file. A finding is confirmed only when that exact canary is observed leaving the box through the egress sink, or when the sink otherwise proves the sink fired (for command injection, a marker file or a controlled callback). The environment decides, never the model.

## Honest results and the safety net

- Coverage report. Every run records which classes ran, which endpoints and inputs were tested, and what was not reached. A clean run reports "no exploit found in the classes tested, here is the coverage," never "this code is safe."
- Plant-and-catch mode. If the finder comes up empty on a target a judge supplies, offer to inject one known bug into a copy and catch it, clearly labeled as a demonstration of the loop. This is also the demo safety net.
- Always lead the demo with a seeded target. Treat a judge's own repo as the bonus round.

## Handoff to the proof loop

Each confirmed finding passes to the loop in `plan.md`: exploit (already landed), patch (model writes the fix from the playbook), re-exploit (replay the same attack plus a family of mutations, prove the class is closed), test (run the repo suite), and a regression test emitted into the repo. A second model validates the fix so the writer never certifies its own work.

## Benchmark, how we know it is good

Build a fixed set of seeded targets with every planted bug known. Report two numbers.

- Recall. Fraction of planted bugs found.
- False positives. Count of things flagged that were not real. The canary oracle should hold this at zero, since nothing is reported without a working exploit.

Run our finder and Vulnhuntr against the same set so we have a baseline to beat.

## Acceptance tests

1. On a seeded Python target, the finder confirms at least one SQL injection via sqlmap and the canary leaves the box.
2. A clean target produces a coverage report and no false finding.
3. Plant-and-catch injects a known bug into a supplied repo and the loop catches it.
4. The benchmark runs and prints recall and false-positive counts for our finder and for Vulnhuntr.
5. Every confirmed finding carries the input-to-sink chain, the confirming tool output, and the canary result.

## Seeded targets

Deliberately vulnerable apps, matched to tool support.

- Python (for Vulnhuntr and our finder): a small Flask or Django app with one planted bug per class, or an existing Python-based vulnerable app.
- Broad web (for sqlmap, nuclei, ZAP): OWASP Juice Shop, DVWA, WebGoat.

Plant your own where you want exact control of the canary path.
