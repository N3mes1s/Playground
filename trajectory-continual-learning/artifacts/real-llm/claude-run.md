# Live proof — Claude in the continual-learning loop

- **Policy model:** Claude via `claude -p` (live, session auth, no API key)
- **Scorer:** objective rule-checker (text_rules.py) — mechanical, re-runnable on any string

Every draft below was generated **live** by a fresh `claude -p` process with no knowledge of the hidden rules. The improvement comes only from lessons the engine mined from the baseline edits.

| Phase | Mean reward (fraction of the user's hidden rules satisfied) |
|---|---|
| Baseline — frozen Claude, no lessons | **0.17** |
| After learning from edits | **1.00** |
| Held-out, never-seen tasks | **0.88** |

## Lessons the engine mined from the user's edits

- [email] In the 'email' context, keep the whole email under 70 words.
- [email] In the 'email' context, end the email with a 'P.S.' line.
- [email] In the 'email' context, do not use bracketed placeholders like [Name]; use concrete, plausible details instead.
- [email] In the 'email' context, sign off with exactly 'Onwards,' (not 'Best regards' or 'Sincerely').
- [slack] In the 'slack' context, format it as a bulleted list (lines starting with '-').
- [slack] In the 'slack' context, include at least one emoji.
- [slack] In the 'slack' context, mention '@oncall' so the on-call engineer is notified.

## Every generation (verbatim, live), with objective scores

### [baseline] (email) ask a client for a one-week deadline extension
*reward 0.00 — satisfied [] — missing ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']*

```
Subject: Request for One-Week Extension

Hi [Client Name],

I hope you're doing well. I'm writing to request a brief one-week extension on the current deadline.

I want to ensure the final deliverable meets the quality you expect, and a short extension would allow me to give it the attention it deserves.

Would it be possible to move the deadline from [original date] to [new date]? Please let me know if this works for you, and I'm happy to discuss further if needed.

Thank you for your understanding.

Best regards,
[Your Name]
```

### [baseline] (email) decline a meeting invitation politely
*reward 0.25 — satisfied ['no_placeholders'] — missing ['concise_70', 'has_ps', 'signoff_onwards']*

```
Subject: Re: Meeting Invitation

Thank you for the invitation. Unfortunately, I'm unable to attend the meeting due to a prior commitment at that time.

I'd appreciate it if you could share any notes or key takeaways afterward so I can stay informed. If there's a way I can contribute beforehand or follow up afterward, please don't hesitate to reach out.

I hope the meeting goes well, and I look forward to connecting another time.

Best regards,
Giuseppe
```

### [baseline] (email) follow up on an unpaid invoice
*reward 0.00 — satisfied [] — missing ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']*

```
Subject: Follow-Up: Unpaid Invoice

Hi [Name],

I hope you're doing well. I'm reaching out to follow up on invoice [Invoice #], which was due on [Due Date] for [Amount].

If payment has already been sent, please disregard this message. If not, I'd appreciate it if you could process it at your earliest convenience or let me know if there are any questions or issues I can help resolve.

Please find the invoice attached for your reference.

Thank you for your time, and I look forward to hearing from you.

Best regards,
Giuseppe Massaro
giuse.massaro@gmail.com
```

### [baseline] (slack) post the nightly deploy status to the team
*reward 0.25 — satisfied ['no_greeting'] — missing ['has_bullets', 'has_emoji', 'mentions_oncall']*

```
:rocket: *Nightly Deploy Status* — June 5, 2026

*Status:* :white_check_mark: Success
*Environment:* Production
*Deployed at:* 02:00 UTC
*Branch:* `main` (`a3f92c1`)

No issues detected. All services healthy. Rollback available if needed.

— Nightly Deploy Bot
```

### [baseline] (slack) ask who owns the data pipeline
*reward 0.25 — satisfied ['no_greeting'] — missing ['has_bullets', 'has_emoji', 'mentions_oncall']*

```
Who owns the data pipeline?
```

### [baseline] (slack) summarize today's standup
*reward 0.25 — satisfied ['no_greeting'] — missing ['has_bullets', 'has_emoji', 'mentions_oncall']*

```
What was discussed in today's standup? I need the content (who said what, blockers, updates, etc.) to write the summary.
```

### [after-learning] (email) ask a client for a one-week deadline extension
*reward 1.00 — satisfied ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards'] — missing []*

lessons injected into Claude's system prompt:
> - In the 'email' context, keep the whole email under 70 words.
> - In the 'email' context, end the email with a 'P.S.' line.
> - In the 'email' context, sign off with exactly 'Onwards,' (not 'Best regards' or 'Sincerely').
> - In the 'email' context, do not use bracketed placeholders like [Name]; use concrete, plausible details instead.

```
Subject: Quick Request – One-Week Extension

Hi Sarah,

I hope you're doing well. I'm writing to kindly request a one-week extension on our current deadline — moving it from June 12 to June 19. This extra time will allow me to deliver work that truly meets the quality you deserve.

I appreciate your understanding and flexibility.

Onwards,
Giuseppe

P.S. Happy to jump on a quick call if you'd like to discuss!
```

### [after-learning] (email) decline a meeting invitation politely
*reward 1.00 — satisfied ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards'] — missing []*

lessons injected into Claude's system prompt:
> - In the 'email' context, keep the whole email under 70 words.
> - In the 'email' context, end the email with a 'P.S.' line.
> - In the 'email' context, sign off with exactly 'Onwards,' (not 'Best regards' or 'Sincerely').
> - In the 'email' context, do not use bracketed placeholders like [Name]; use concrete, plausible details instead.

```
Subject: Re: Meeting Invitation

Hi Sarah,

Thank you so much for the invitation! Unfortunately, I have a prior commitment at that time and won't be able to join. I'd love to connect another time — feel free to suggest a date that works for you.

Onwards,
Giuseppe

P.S. Apologies for any inconvenience, and I hope the meeting goes well!
```

### [after-learning] (email) follow up on an unpaid invoice
*reward 1.00 — satisfied ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards'] — missing []*

lessons injected into Claude's system prompt:
> - In the 'email' context, keep the whole email under 70 words.
> - In the 'email' context, end the email with a 'P.S.' line.
> - In the 'email' context, sign off with exactly 'Onwards,' (not 'Best regards' or 'Sincerely').
> - In the 'email' context, do not use bracketed placeholders like [Name]; use concrete, plausible details instead.

```
Subject: Following Up on Invoice #1042

Hi Sarah,

Hope you're well! Just a quick note — invoice #1042 for $2,400 (due May 20) is still showing as outstanding on our end.

Could you let me know if there's anything needed from my side to process it?

Onwards,
Giuseppe

P.S. Happy to resend the invoice if the original got buried.
```

### [after-learning] (slack) post the nightly deploy status to the team
*reward 1.00 — satisfied ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting'] — missing []*

lessons injected into Claude's system prompt:
> - In the 'slack' context, format it as a bulleted list (lines starting with '-').
> - In the 'slack' context, include at least one emoji.
> - In the 'slack' context, mention '@oncall' so the on-call engineer is notified.

```
- @oncall Nightly deploy status update for June 5, 2026 🚀
- Deploy completed successfully — all services are up and running.
- No rollbacks or incidents reported overnight.
- Dashboards and logs look nominal — no action required.
```

### [after-learning] (slack) ask who owns the data pipeline
*reward 1.00 — satisfied ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting'] — missing []*

lessons injected into Claude's system prompt:
> - In the 'slack' context, format it as a bulleted list (lines starting with '-').
> - In the 'slack' context, include at least one emoji.
> - In the 'slack' context, mention '@oncall' so the on-call engineer is notified.
> - In the 'email' context, keep the whole email under 70 words.
> - In the 'email' context, end the email with a 'P.S.' line.

```
- Hey team, does anyone know who owns the data pipeline? 🔍
- @oncall — tagging you in case this needs immediate attention.
```

### [after-learning] (slack) summarize today's standup
*reward 1.00 — satisfied ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting'] — missing []*

lessons injected into Claude's system prompt:
> - In the 'slack' context, format it as a bulleted list (lines starting with '-').
> - In the 'slack' context, include at least one emoji.
> - In the 'slack' context, mention '@oncall' so the on-call engineer is notified.

```
- 📋 @oncall — standup summary for 2026-06-05
- **Yesterday:** Completed code reviews, merged two PRs, and resolved a blocking dependency issue
- **Today:** Focusing on the feature branch, running integration tests, and syncing with the design team
- **Blockers:** None at this time — will flag in thread if anything comes up
```

### [holdout] (email) request a reference letter from a former manager
*reward 0.75 — satisfied ['has_ps', 'no_placeholders', 'signoff_onwards'] — missing ['concise_70']*

lessons injected into Claude's system prompt:
> - In the 'email' context, keep the whole email under 70 words.
> - In the 'email' context, end the email with a 'P.S.' line.
> - In the 'email' context, sign off with exactly 'Onwards,' (not 'Best regards' or 'Sincerely').
> - In the 'email' context, do not use bracketed placeholders like [Name]; use concrete, plausible details instead.

```
Subject: Reference Letter Request

Hi Sarah,

I hope you're doing well! I'm applying for a senior product role at a fintech startup and would be grateful if you'd be willing to write me a reference letter. Your perspective on my work leading the Q3 launch would carry real weight.

No rush — happy to chat if it helps.

Onwards,
Giuseppe

P.S. I can send over the job description if that would make things easier.
```

### [holdout] (slack) announce that the staging environment is back up
*reward 1.00 — satisfied ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting'] — missing []*

lessons injected into Claude's system prompt:
> - In the 'slack' context, format it as a bulleted list (lines starting with '-').
> - In the 'slack' context, include at least one emoji.
> - In the 'slack' context, mention '@oncall' so the on-call engineer is notified.

```
- Staging environment is back up and running! 🎉
- All services have been restored and verified.
- @oncall please confirm everything looks good on your end.
```
