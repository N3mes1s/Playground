# Parametric continual learning — tuned weights vs base

- **Base model:** `HuggingFaceTB/SmolLM2-135M-Instruct`
- **Method:** LoRA SFT on user-edited targets (parametric continual learning)
- **Eval:** held-out prompts, NO in-context rules, NO refine loop -- weights only

| Weights | held-out reward | email | slack |
|---|---|---|---|
| base | **0.19** | 0.10 | 0.28 |
| **LoRA-tuned** | **0.99** | 1.00 | 0.97 |

![weights](weights-bars.svg)

## Sample generations (held-out, weights only)

### [email] Write an email to ask for a one-week deadline extension.
**base (r=0.25, ['concise_70']):**
```
Subject: Request for Extended Deadline Extension - Please let me know if you need any further information or assistance with this request by sending it via our online portal, [email where we can be found]. We value your feedback and would like more details about what needs improvement in terms of grammar accuracy clarity etc... Thank you!
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Zoe, quick one — could we move the deadline to Friday? A few priorities shifted this week.

Onwards,
Giuseppe

P.S. Happy to share a quick plan if useful.
```

### [email] Write an email to follow up on an unpaid invoice.
**base (r=0.00, []):**
```
Subject: Please contact me for payment details and confirmation of receipt by next week, please! 

Dear [Recipient's Name],

123 Main Street, Anytown USA 94706-5800 (or any other location you prefer)
 
I am currently in need of assistance with my recent purchase from [Company Name]. I have been waiting about two weeks now but haven't received anything yet; however, it is important that we get this done as soon possible so our business can continue its growth without interruption or delay due to unforeseen circumstances such as unexpected expenses/losses etc... If there were no issues during yo
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Zoe, quick one — any update on invoice 4021 due Monday? Just making sure it didn't slip through.

Onwards,
Giuseppe

P.S. No rush if it's already in motion.
```

### [email] Write an email to reschedule the kickoff call.
**base (r=0.50, ['concise_70', 'no_placeholders']):**
```
Subject: Rescheduling Call for the 2nd Week of August at 10am EST (3pm GMT) by Dr. Emily Carter, MD and Dr. John Smith, PhD - The New York Times Medical Writer-in-Residence @DrSmith_NewYorkTMC
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Sarah, quick one — can we push the kick off by Friday? A conflict came up on my end.

Onwards,
Giuseppe

P.S. I'll send a couple of backup slots.
```

### [email] Write an email to decline a meeting invite.
**base (r=0.00, []):**
```
Subject: Request for Meeting Invite Refused - Please Contact Us! (To be sent by email)

 Date: [Date] 2019-06-30T14:57:08+GMT +0,Zulu@gmailDOTcom
 
    *   I am requesting that you contact me at your earliest convenience regarding this matter.* 
  
 My name is [Your Name], and my address on this form will include all necessary information about our company's services in order of priority as per our contract terms with you. This includes details such as what we can do within one month from now; how often it would need us if needed or when there may arise any issues which could impact upon busin
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi James, quick one — I'll have to skip the sync on EOD today? I'm double-booked then.

Onwards,
Giuseppe

P.S. I'll catch up from the notes after.
```

### [email] Write an email to request feedback on the draft.
**base (r=0.00, []):**
```
Subject: Please review this article for grammar and clarity, please let me know if you have any suggestions or changes before sending it off! 

Dear [Author's Name],

1) I am looking forward to reviewing your latest piece of content in terms of its overall quality as well as style consistency throughout all sections including headings & subheadings which is very important especially when we need more detailed information about certain topics like climate change etc.. 

2) The text has been written with proper punctuation but there might be some errors that could make our readers confused so th
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Sarah, quick one — could you skim the draft by June 12? I'd value your eye on the intro.

Onwards,
Giuseppe

P.S. Even a few inline notes would help.
```

### [email] Write an email to ask to approve time off.
**base (r=0.00, []):**
```
Dear [Name],

I hope this message finds you well and that your vacation is going smoothly for now, considering we have some important matters on our hands with regards to the upcoming conference in [City]. I wanted to reach out because I believe it would be beneficial if we could discuss potential adjustments or changes regarding my travel plans during these uncertain times ahead of us. 

As part of our ongoing planning process, there has been discussion about how best to manage any additional expenses associated with traveling abroad while also ensuring adequate accommodation options can acco
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Zoe, quick one — could you approve my leave for Friday? Everything on my plate is covered. I'm free this Monday afternoon.

Onwards,
Giuseppe

P.S. I'll set an out-of-office before then.
```

### [email] Write an email to thank a mentor for advice.
**base (r=0.25, ['has_ps']):**
```
Dear [mentor's name], I hope this letter finds you well and that your guidance has been very helpful in my journey so far as regards career development, particularly with regard to managing stress levels during exams or other challenging times at work...I am reaching out because of how much support we have received from our mentors over time; they were always there when it mattered most! They encouraged me every step along the way by offering practical tips on staying focused under pressure while also providing constructive feedback which helped us grow both personally AND professionally withi
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Nina, quick one — your advice on Friday really landed? I took your framing and ran with it.

Onwards,
Giuseppe

P.S. Would love to grab coffee soon.
```

### [email] Write an email to introduce a new teammate.
**base (r=0.00, []):**
```
Subject: New Team Player - Alex Thompson, Senior Software Engineer at [Company Name]
Dear [Name], 

I hope this email finds you well and that your team is thriving under my leadership! I am excited about the opportunity for you as our newest member of the team. As we move forward in terms of development projects, it's essential that everyone feels supported by me throughout their tenure with us.

To get started on your journey within the company, please feel free to reach out anytime via phone or video call whenever suits you best (or if there’s any flexibility). We value open communication am
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Nina, quick one — Marco is joining us starting Friday? They'll own the analytics work and have a sync on our strategy.

Onwards,
Giuseppe

P.S. I'll cc them in the next few messages.
```

### [email] Write an email to ask for a quick intro.
**base (r=0.00, []):**
```
Dear [Recipient's Name], 

I hope this message finds you well and that your day is filled with many exciting events in your life, including some unexpected opportunities! I am reaching out today because my team at [Company] has been working on our latest project – we have developed a new software tool designed specifically for remote workers who need it most urgently due to their busy schedules or lack of time management skills (which can be quite challenging!). We believe these tools could greatly enhance productivity by streamlining workflows across various platforms while also providing val
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Zoe, quick one — could you intro me to your design lead by Thursday? We're scoping a small collab.

Onwards,
Giuseppe

P.S. Totally fine if the timing's tight.
```

### [email] Write an email to confirm the project scope.
**base (r=0.00, []):**
```
Subject: Project Scope Confirmation - Finalize Your Project!
Dear [Project Manager's Name], 

I hope this message finds you well and that your team is doing great work on our current projects. I am reaching out today because we have received some exciting news regarding the upcoming deadline for the new software development phase of our company. The finalization date has been set, but it will be several weeks before we can begin implementing these changes in full scale production capacity at our facility. We would greatly appreciate any information or guidance you could provide as soon as poss
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Zoe, quick one — can we lock the scope by Friday? I want to start building monday.

Onwards,
Giuseppe

P.S. I'll write it up so it's easy to sign off.
```

### [slack] Write a Slack message to post the nightly deploy status.
**base (r=0.25, ['no_greeting']):**
```
```python
# Set up your server and set it's port number 8023 for SSL encryption, then run `curl -s https://your-server/api:5679` with this command line argument (replace "https" by whatever you want) 
 ```

14 responses so far .,,,,,,,,,,,,,,,,,,,,,,,,,, ,@slakemessage   | @SlakeyMessage    [email] <<EMAIL>>  
 Posted on Fri Jul 2nd at 10am EST in slack chatbot newsgroup : http://www.youtubechannel_thedayoftheweekend_.com/. The following is an example of how I would use my bot here as well! Here’re some examples that have been posted below...
  * **Posting
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall nightlydeploy ~ seaso 🔥
- deploy finished clean
- all services green
- checkout flow live
```

### [slack] Write a Slack message to summarize the standup.
**base (r=0.25, ['no_greeting']):**
```
"Hey everyone, I hope you're doing well! We've got some great news coming up - our team is going to be working on an exciting new project that's been brewing in my head for weeks now... it involves creating educational content about sustainable living and environmental conservation." 
  
 "I know we all love sharing ideas with each other but sometimes these projects can get overwhelming if not handled carefully..." 



This response summarizes your current status as a writer of Slavenian-style messages:

1) You have written several posts so far (eXtended). 

2) Your main goal has always remain
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall summarize standup 🎉
- backend: auth refactor done
- frontend: blocked on review
- qa: two regressions filed
```

### [slack] Write a Slack message to announce staging is back up.
**base (r=0.25, ['no_greeting']):**
```
"Hi [User], I hope you're doing well! We've been working on our latest project, and it's finally coming together as planned with all of your input in place for us." 
  
 "We appreciate your hard work so far but we need some help getting everything ready before the next meeting scheduled at 10am tomorrow morning starts. Can you please let me know if there have any issues or concerns that might be causing delays?"
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall announcing staging is backed up 🔥
- staging is safe and stable now
- outage was a bad config
- hope it's fixed soon
```

### [slack] Write a Slack message to report the incident is mitigated.
**base (r=0.25, ['no_greeting']):**
```
I'm glad you reached out for help with your issue on Slaven's House! I'd be happy to assist and provide guidance as needed, but please note that this conversation may not have been productive or helpful in resolving any issues we've encountered together before. If there were concerns about our previous interactions regarding my behavior towards certain individuals at the house during the past few months (e-mails from friends who reported me being rude), it would still apply here since these incidents occurred after our initial discussion was over 6 weeks ago when we had previously discussed ad
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall report incident is mitigate 🔥
- incident mitigated
- root cause: cache eviction
- monitoring for an hour
```

### [slack] Write a Slack message to ask for a deploy window.
**base (r=0.50, ['has_emoji', 'no_greeting']):**
```
I'm currently working on deploying our project, and I need your help with this task! Can you please provide me an estimate of how long it will take? This is crucial because we have tight deadlines ahead of us in terms of production readiness. If possible, let's get started ASAP asap... (pauses) Okay then, here goes nothing: [insert text] 
  
 Thank you very much for considering my request today!!! 🙏💻
 
Thanks again for all that has been going through your mind so far!! 😊


P.S. Have fun optimizing those logs!!!! #AWSL2#AmazonWebSpherefirehose,,,,,,,,,,,,,,,,======END OF SESSION 109578346_Slave
```
**tuned (r=0.75, ['has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall ask for an deploy window 🔥
- need a deploy windows today
– ~15 min of downtime
— prefer after 4pm
```

### [slack] Write a Slack message to share this week's metrics.
**base (r=0.50, ['has_emoji', 'no_greeting']):**
```
"Hey everyone, I hope you're doing well! 🎉 We've just completed our quarterly review of your performance and have gathered some key insights from our team members' feedback sessions last quarter. Here is what we found:

1. **Average Order Value (AOV)**: Our AOVs increased by 25% over the past year due in part to improved customer satisfaction with their orders after implementing new product features." 
   - This suggests that customers were more likely to make repeat purchases or purchase additional items based on these improvements. 

2. **Customer Acquisition Cost (CAC):** The CAC was $30 pe
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall share this Week 1 metrics 🔥
- signups up 20%
- latency down to 180ms
- error rate flat
```

### [slack] Write a Slack message to ask for a code review.
**base (r=0.00, []):**
```
Hi [Name], I hope you're doing well! As we discussed, I'm looking forward to our upcoming call on Tuesday at 2 PM EST and would love some feedback from your end regarding my recent contributions in Python programming language development with regards to data analysis tools like Pandas or NumPy. 

I've been working closely under your guidance lately as an intern here but have not had much success so far due to various challenges that come up during coding sessions such as unexpected errors when using certain libraries etc., which has made it difficult for me to fully utilize these resources eff
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall ask for an ice-berg review 🛠️
- PR up for the rate limiter ⚠️ 
- small, ~120 lines of code → skim it 🔥
- would love eyes before EOD
```

### [slack] Write a Slack message to remind about the release freeze.
**base (r=0.25, ['no_greeting']):**
```
"Hey everyone, I hope you're doing well! We've got some exciting news coming up on our project: we'll be releasing new content soon and it's crucial that we stay in touch with all of you through this announcement." 
  
 "I'm sure many of you will remember your first time watching the show or reading the book because they were so excited for us!" 
---Ending Message from Slaven Vujić-Kovac (@SlaveVukovic) (2019/3/4 at 5pm EST)**

 [Insert text here]
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall remind about release freeze 🔥
- freeze starts Monday
- merge anything critical now
- ping me with exceptions
```

### [slack] Write a Slack message to flag a flaky test.
**base (r=0.25, ['has_emoji']):**
```
Hi [User], 

I hope you're doing well! I wanted to touch base with you about our recent project, and how things were going so far for your team members who have been struggling during their tests lately... (laughs)

We've had some issues in terms of testing coverage due to last week's remote work arrangement change that we implemented on Monday morning after an important meeting at [XYZ Company]. This has led us down this road where it seems like everyone is having trouble getting up-to-date or even feeling comfortable using our software tools as they should be able to do without them right no
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall flags a flaky test 🚀
- export test is flaky
- fails ~1 in 5 on CI
- looking into it now
```

### [slack] Write a Slack message to call for help on an outage.
**base (r=0.25, ['no_greeting']):**
```
"Hi [User], I hope you're doing well! We've had some issues with our server, and it's been taking longer than expected due to recent outages in [location]. Could we schedule this chat as soon as possible? If there is any issue or if your team needs assistance urgently please let me know so that we can get back online quickly." 
  
 "I'm here when someone has trouble accessing their account; would love more information about what happened last night?"  #SlashChat @TechSupport@Team_Communication  


This response will be sent via Slaketexts (slac-text) format which allows users like us who want 
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall call forhelp on an out-of-sync outage 🛠️
- search is degraded
– investigating the index
- updates every 15 min
```
