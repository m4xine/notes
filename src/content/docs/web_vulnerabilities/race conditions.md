---
title: Race Conditions
description: When a web application processes requests concurrently without proper synchronization, a race condition can occur, leading to unexpected or insecure outcomes.
---
A race condition happens when two or more threads/processes access shared data at the same time, and the result depends on the order in which they run.

For example, two users try to withdraw money at the same time.
If both see the same balance before it updates, they could both withdraw — causing overdraft.
## Types of Race conditions
### Limit overrun 
When user is able to bypass restrictions. For example:
- Redeeming gift card
- Rating product multiple times
- Withdrawing or transferring cash in excess of your account balance
- Reusing a single CAPTCHA solution
- Bypassing an anti-brute-force rate limit

### Single Point
- There's one place in the code (a “single point”) that checks something important (like “has the user already redeemed a reward?”).
- If multiple requests hit that point at the same time, they all pass, because the system hasn’t updated yet.
### Multiple Endpoint
A multiple endpoint race condition happens when two or more different API endpoints affect the same resource or action, and calling them at the same time leads to unintended behaviour.

## Exploit
![](../../../../public/images/Race_Conditions_20250612%20_225920.png)
### Predict
1. Is this endpoint security critical?
2. Can multiple requests hit the same backend logic or record at the same time?
3. Is the system using shared state or updating something based on a check like if not used → "If the thing hasn’t been used yet, go ahead and do something."
### Probe
1. Check normal behaviour, grouping all of your requests and using the Send group in sequence (separate connections) option.
2. Send the same group of requests at once using Send group in parallel option.
3. Look for unexpected behaviour caused by two or more requests interfering with each other.
	 - Does it deny access?
	 - Slow down?
	 - Display error?
	 - Analyse timing

### Prove the concept
- Isolate requests that caused interference during probing
- Replay them at the same time using Send group.
- Observe whether the outcome changes (e.g. duplicate action, logic bypass, inconsistent state)
- Try modifying inputs or endpoints while racing to explore further impact

### Connection warming
When you test for race conditions, sometimes your first request takes longer than the others. This isn’t always because of the app — it can be due to network or server connection setup.

That’s what they call connection warming:
You send a harmless request (like `GET /`) first, so the server finishes setting up the connection before your actual test begins.

If that first request is still slow, but the rest come fast and close together, it means the slowness was just connection overhead, not a real problem.
## References
- [Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine#methodology)
- [Race Condition allows to redeem multiple times gift cards which leads to free "money"](https://hackerone.com/reports/759247)
- [Race Condition in Flag Submission](https://hackerone.com/reports/454949)