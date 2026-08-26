# Validation outreach

Drafts for getting the Detection Lab in front of real detection engineers. The
goal is a signal, not signups: does "score your rule against per-event-labelled,
seeded telemetry and see the exact benign events it fires on" make them lean in?

Post, then **watch for the reaction** (see the last section). Lead with the tool,
not the company. Ask for honest criticism, a shrug is useful data.

The link everywhere: **https://wallfacerj.github.io/endomorph/?lab**

---

## r/detectionengineering (or r/blueteamsec)

**Title:** I built a browser tool that scores your Sigma rule against labelled, seeded telemetry, and shows the exact benign events it fires on

**Body:**

Testing a detection rule usually means guessing at its false-positive rate,
because a captured dataset has one world and hand-applied labels. I built a
generator where the *ground truth is known by construction*, every event is
labelled benign or malicious and mapped to an ATT&CK technique before it's
written, and put a scorer in the browser on top of it.

Paste a Sigma rule here and it gives you true positives, false positives, and
recall counted against known truth, then lets you open the rule to see the
**exact benign events** it's catching. No login, no download:

https://wallfacerj.github.io/endomorph/?lab

There are example rules in the box if you don't want to write one, try "Any
PowerShell" and open it to see the 188 benign admin scripts it flags at 2%
precision.

Two things I'd genuinely like to know:
1. Is seeing the specific false positives (not just a number) useful, or is it
   noise?
2. The CLI can score a rule across many *seeded* enterprises, same techniques,
   different staff/hosts/addresses, to check whether it generalises or just
   memorised one world. Is "does my rule survive when the environment changes"
   a question you'd use?

It's a solo project and I'm trying to find out if this solves a real problem or
a made-up one. Brutal feedback welcome.

---

## Detection Engineering / SOC Slack or Discord (short)

Built a browser tool that scores a Sigma rule against telemetry where every
event is labelled benign/malicious by construction, so precision and recall are
counted, not estimated, and you can open a rule to see the exact benign events
it fires on. Example rules included, no login: https://wallfacerj.github.io/endomorph/?lab

Would love to know if the false-positive drill-down is useful or if I'm solving
a problem nobody has. 🙏

---

## X / Mastodon / LinkedIn (short)

Detection engineers: paste a Sigma rule, get precision/recall counted against
ground-truth-labelled telemetry, and open the rule to see the *exact* benign
events it false-positives on. In the browser, no login.

https://wallfacerj.github.io/endomorph/?lab

Does seeing the specific FPs (not just the rate) change how you'd tune it?

---

## Direct DM (Sigma / detection-content maintainers)

Hi, I saw your work on [their rules/repo]. I built a small browser tool that
scores a Sigma rule against telemetry with per-event ground truth (labelled by
construction, not by hand), and shows the exact benign events a rule fires on.
Since you write rules against real-world noise, I'd value your read on whether
the false-positive breakdown is actually useful or just a demo trick:
https://wallfacerj.github.io/endomorph/?lab

No ask beyond an honest reaction. Thanks for considering it.

---

## What to watch for (the actual experiment)

You're testing one hypothesis: **detection engineers want counted precision and
a false-positive breakdown against realistic, labelled telemetry.**

- **Strong signal:** they paste a *real* rule of their own (not just click an
  example), react to a specific false positive, ask whether they can point it at
  their own environment/ruleset, or share the link onward.
- **Weak signal:** "neat," a like, silence, or "how is this different from
  [Attack Range / Splunk BOTS / a public dataset]" with no follow-up.
- **Disconfirming:** "my FP numbers come from prod, synthetic won't transfer" , 
  and the noise-floor measurement (`pnpm noise-floor`, or the manifest's
  difficulty figures) doesn't change their mind.

Five to ten reactions is enough to know which way this points. If it leans
positive, the next build is worth it (more ATT&CK coverage, point-it-at-your-own-
ruleset). If it leans negative, you learned it in a week instead of a quarter,
and the console-as-training path is the fallback.
