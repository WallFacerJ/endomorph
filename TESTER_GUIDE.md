# Polymorph v1 First-Time Tester Guide

Thanks for testing Polymorph v1. The goal of this test is to find out whether a new user can understand and complete a cybersecurity investigation without someone explaining the interface first.

## What you need

- A desktop or laptop browser. Current Chrome, Edge, Firefox, or Safari should work.
- About 10–15 minutes for one scenario, or 20–30 minutes to try all three.
- No Polymorph experience is expected. Cybersecurity experience is helpful but not required.
- Start in **Student mode**. Do not switch to Instructor mode until after you have finalized at least one investigation, because instructor mode contains ground truth.

## Recommended first test

1. Open the shared Polymorph link.
2. Leave the default scenario selected and stay in **Student mode**.
3. Without reading source code or this repository's scenario JSON, try to answer these questions through the product:
   - What appears to have happened?
   - Which user/account/device are involved?
   - Which telemetry is meaningful evidence?
   - What response actions should you take?
4. Open the alert and investigate the correlated timeline.
5. Pivot through **Endpoint** and **Identity** if they look useful.
6. Collect at least two pieces of evidence.
7. Open **Case**, select evidence, and save one finding in your own words.
8. Return to the investigation and choose whatever response actions you think are appropriate. Do not try to guess what the app wants; act on the evidence.
9. Click **Finalize investigation**.
10. Review the objective completion, response-quality penalty, and final score. Decide whether the result makes sense to you.
11. Try one of these follow-ups:
    - **Reset scenario** and verify the run is clean again.
    - Switch to a different scenario with the scenario selector.
    - After a completed run, switch to **Instructor mode** and compare your conclusion with the authored ground truth.

## Things we specifically want to learn

Please pay attention to these areas while testing:

- **First impression:** Could you tell what the product was for and what you should do first?
- **Navigation:** Could you find the alert, timeline, endpoint, identity, and case views without help?
- **Evidence:** Was it obvious how to collect evidence and use it in a finding?
- **Response actions:** Did the choices feel understandable and consequential?
- **Finalization:** Was it clear that finalizing submits/freezes the investigation?
- **Scoring:** Did the difference between objective completion, response penalty, and final score make sense?
- **Instructor review:** After finalization, was the ground-truth comparison useful?
- **Scenario switching:** Did moving between scenarios feel clean and predictable?
- **Reset:** Did reset return everything—including evidence, findings, actions, score, and finalization—to a fresh state?
- **Realism:** Which parts felt convincing, artificial, confusing, or too obvious?

## Optional edge-case checks

If you have time, deliberately test behavior that might break:

- Finalize without taking any response action.
- Finalize after only one beneficial response action.
- Take the obviously risky **Restore account access** action and see whether the post-incident penalty is explained clearly.
- After finalization, try to collect evidence, edit finding fields, submit another finding, or perform another response action. The finalized case should be read-only until reset.
- Change scenarios after doing work in the current one and make sure the new scenario does not inherit old case state.
- Refresh the browser during an active run. v1 is intentionally local/in-memory, so a refresh starts a fresh run; note whether that behavior surprises you.

## Feedback template

You can send this directly to the person who shared Polymorph with you. A GitHub account is not required unless you want to file an issue yourself.

```text
Polymorph v1 tester feedback

Browser + OS:
Scenario tested:
Cybersecurity experience (none / some / professional):

1. What did you think your goal was when the page first loaded?
2. What was the first place you got confused or slowed down?
3. Could you collect evidence and write a finding without help?
4. Which response action(s) did you choose, and why?
5. Did the final score/result make sense? If not, what was unclear?
6. What felt most realistic or useful?
7. What felt fake, too obvious, or unnecessary?
8. Did anything look broken or behave unexpectedly?
9. What is the one change that would most improve the experience?

Bug details, if any:
- Steps to reproduce:
- Expected result:
- Actual result:
- Screenshot/video if available:
```

## Tester privacy and safety

Polymorph scenarios use synthetic data. Do not enter real credentials, secrets, personal information, or production incident data into findings. v1 runs entirely in the browser and does not provide durable run persistence or real multi-user authentication.

## Instructor mode note

Instructor mode is a local presentation feature for comparing a completed run with authored ground truth. It is **not** an authentication or authorization boundary in v1. Anyone with the test URL can switch modes, so use it for testing and review—not for protecting assessment answers in a real classroom deployment.
