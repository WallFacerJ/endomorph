# Polymorph v1 Quick Tester Guide

Thanks for trying Polymorph. You do **not** need to learn the project or read documentation before testing it. We mainly want to know whether the product makes sense without explanation.

## The five-minute test

1. Open the shared Polymorph link and stay in **Student mode**.
2. Open the alert and investigate until you think you understand what happened.
3. Collect one or two pieces of evidence. If it feels natural, write one finding in **Case**.
4. Choose the response action(s) you think are right, then click **Finalize investigation**.
5. Send us four things:
   - What did you think you were supposed to do?
   - Where did you hesitate or get confused?
   - Did the final result/score make sense?
   - What one change would improve the experience most?

That is enough for a useful first-time test.

## If you have another five minutes

Try any of these only if you want to:

- Switch to another scenario and see whether the workflow still feels obvious.
- Change **Style** between **Midnight SOC** and **Graphite** and tell us which feels more professional/readable.
- Finalize after only one useful response action and see whether the partial result makes sense.
- Take a risky response action and see whether the post-incident penalty is explained clearly.
- After finalization, try to change evidence, findings, or response actions. The submitted case should remain read-only until reset.
- Reset the scenario and confirm that evidence, findings, actions, score, and finalization all return to a clean state.
- After finishing a run, switch to **Instructor mode** and compare your conclusion with the authored ground truth.

## What not to worry about

You are not being tested on cybersecurity knowledge. Wrong choices are useful feedback if the interface or evidence led you there.

You also do not need to deliberately hunt for bugs. If something looks wrong, feels awkward, or does not behave how you expected, just tell us what you were trying to do.

## Easy feedback template

Copy/paste this into a message if you do not want to file a GitHub issue:

```text
Polymorph feedback

Browser / OS:
Scenario:
Cybersecurity experience: none / some / professional

What I thought I was supposed to do:
Where I got confused or slowed down:
Did the final result/score make sense?:
Best part:
One thing I would change:
Anything broken or unexpected:
Preferred style: Midnight SOC / Graphite / no preference
```

## Technical/local fallback

For testers who want to run Polymorph locally instead of using the hosted site:

```bash
git clone https://github.com/WallFacerJ/polymorph.git
cd polymorph
pnpm install --frozen-lockfile
pnpm dev
```

Use Node 24 and pnpm 11.22.0. Vite will print the local URL, normally `http://localhost:5173/`.

## Privacy and safety

Polymorph uses synthetic scenarios. Do not enter real credentials, secrets, personal information, or production incident data into findings.

v1 runs in the browser and does not provide durable run persistence or real multi-user authentication. Refreshing during an active run starts a fresh run.

## Instructor mode

Instructor mode is for post-run comparison with authored ground truth. It is a presentation feature, not an authentication boundary. First-time testers should stay in Student mode until they have finalized at least one investigation.
