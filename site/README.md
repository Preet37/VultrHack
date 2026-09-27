# Cerberus — showcase site (`site/`)

The judge-facing demo page for **Blast Radius Zero**. A single self-contained
`index.html` (no build step, no dependencies, no network calls, no secrets). It
tells the whole Cerberus story with motion design: type a repo URL → the control
plane dispatches into a disposable **gVisor VM window** → a live terminal streams
the **find → prove (canary) → patch → re-prove → certify** loop → the isolation
probe is **BLOCKED** with the real kernel `DROP` log → the VM is torn down (404).

**For Sasha (and anyone pulling this):** this is the *presentation layer only*.
It is intentionally static and driven by **real captured data** (the actual five
vuln classes + endpoints, the real `4.19.0-gvisor` uname, the real
`cerberus-os-drop` kernel log line, the real `deepseek-v4-flash-0731` model, the
five demo checkpoints). It does **not** call the backend, so it always works on
stage and holds no keys. Nothing here changes the engine — edit `index.html` for
copy/visuals; leave the finder/control-plane code alone.

## Run locally

```sh
cd site
python3 -m http.server 8080      # then open http://127.0.0.1:8080
```

(Open over http, not `file://` — the background canvas needs a real origin.)

## Deploy (Vercel)

It's a pure static site, so any static host works. With the Vercel CLI:

```sh
cd site
vercel deploy --prod        # first run links/creates the project; root = this dir
```

Or in the Vercel dashboard: import the repo, set **Root Directory = `site`**,
framework preset **Other** (no build command, output = the directory itself).

## What maps to the rubric

The page has a **Rubric** section that answers each judge question directly
(VM backend → "show me the instance"; Vultr inference → "yours or a borrowed
key?"; orchestration → "planning/dispatching or a static page?"; isolation →
"if I paste `rm -rf /`, what dies?"), an **Isolation tiers** ladder (we run
gVisor / tier 3 on a disposable VX1), and the **two-instance architecture**
diagram. It is the same five checkpoints the sandbox smoke job proves live.
