# Parametric continual learning — tuned weights vs base

- **Base model:** `HuggingFaceTB/SmolLM2-135M-Instruct`
- **Method:** LoRA on user-edited signal (tag=dpo_anchored)
- **Eval:** held-out prompts, NO in-context rules, NO refine loop -- weights only

| Weights | held-out reward | email | slack |
|---|---|---|---|
| base | **0.19** | 0.10 | 0.28 |
| **LoRA-tuned** | **0.78** | 0.55 | 1.00 |

![weights](weights-bars.svg)

## Sample generations (held-out, weights only)

### [email] Write an email to ask for a one-week deadline extension.
**base (r=0.25, ['concise_70']):**
```
Subject: Request for Extended Deadline Extension - Please let me know if you need any further information or assistance with this request by sending it via our online portal, [email where we can be found]. We value your feedback and would like more details about what needs improvement in terms of grammar accuracy clarity etc... Thank you!
```
**tuned (r=0.50, ['concise_70', 'no_placeholders']):**
```
Hi Alex, quick one: I need your availability in 2 weeks on Wednesday so we can discuss our project plan and start planning next week! Can't wait to hear from you soon. Onwards? 🙌

Onward with that—on Tuesday or Thursday if possible (or Friday)?
Best,
Emily
```

### [email] Write an email to follow up on an unpaid invoice.
**base (r=0.00, []):**
```
Subject: Please contact me for payment details and confirmation of receipt by next week, please! 

Dear [Recipient's Name],

123 Main Street, Anytown USA 94706-5800 (or any other location you prefer)
 
I am currently in need of assistance with my recent purchase from [Company Name]. I have been waiting about two weeks now but haven't received anything yet; however, it is important that we get this done as soon possible so our business can continue its growth without interruption or delay due to unforeseen circumstances such as unexpected expenses/losses etc... If there were no issues during yo
```
**tuned (r=0.75, ['has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Alex, quick one — I just got back from a meeting with the vendor and they're still not responding! Can we chat soon? Also, did you catch the deadline for that invoiced payment in the inbox this morning?

Onwards,
Giuseppe
- Giusita Giovanni 12:05 GMT +3
-- Gianluca Giuliano 48976 GMT -1


P.S., can't wait to hear your takeaway today 🎉 . #invoice_email @giuzzano@gmail.com



Feel free to add or remove content as needed 😊
```

### [email] Write an email to reschedule the kickoff call.
**base (r=0.50, ['concise_70', 'no_placeholders']):**
```
Subject: Rescheduling Call for the 2nd Week of August at 10am EST (3pm GMT) by Dr. Emily Carter, MD and Dr. John Smith, PhD - The New York Times Medical Writer-in-Residence @DrSmith_NewYorkTMC
```
**tuned (r=0.75, ['concise_70', 'no_placeholders', 'signoff_onwards']):**
```
Hi Michael, quick one — we've got some issues with our deadline for the kick-offs today. Can you take a look at that? I'll send it over and make sure everything's on track by then. Also, can you confirm if there were any changes in your schedule this morning or last night due to traffic congestion?

Onwards,
Alex
```

### [email] Write an email to decline a meeting invite.
**base (r=0.00, []):**
```
Subject: Request for Meeting Invite Refused - Please Contact Us! (To be sent by email)

 Date: [Date] 2019-06-30T14:57:08+GMT +0,Zulu@gmailDOTcom
 
    *   I am requesting that you contact me at your earliest convenience regarding this matter.* 
  
 My name is [Your Name], and my address on this form will include all necessary information about our company's services in order of priority as per our contract terms with you. This includes details such as what we can do within one month from now; how often it would need us if needed or when there may arise any issues which could impact upon busin
```
**tuned (r=0.50, ['concise_70', 'no_placeholders']):**
```
Hi Alex, quick one — I'm on it with this 15-minute agenda for today? Can we chat about that later tomorrow instead of tonight?

Onwards! 🙌

2 PM EST or anytime next week works too if you're up for something more relaxed 😊

Cheers,
Emily
```

### [email] Write an email to request feedback on the draft.
**base (r=0.00, []):**
```
Subject: Please review this article for grammar and clarity, please let me know if you have any suggestions or changes before sending it off! 

Dear [Author's Name],

1) I am looking forward to reviewing your latest piece of content in terms of its overall quality as well as style consistency throughout all sections including headings & subheadings which is very important especially when we need more detailed information about certain topics like climate change etc.. 

2) The text has been written with proper punctuation but there might be some errors that could make our readers confused so th
```
**tuned (r=0.00, []):**
```
Hi Alex, quick one — I've reviewed your section and it looks great! You're right about the structure being solid; just tweak that last sentence for clarity: "The revised paragraph is now clear." Let me know if you need any further tweaks or have questions?
- @Alex@writing_advice 📚👩‍➌

2019-365 #WritingAdvices 47 (8)
[email protected] [website]: https://www.facebook.com/williamdavidson / twitter (@alexviddox ) 
  
 Thanks in advance for catching this early—I'll get back with more details soon 😊 .
– @AlanDV|•← Back To Writing
```

### [email] Write an email to ask to approve time off.
**base (r=0.00, []):**
```
Dear [Name],

I hope this message finds you well and that your vacation is going smoothly for now, considering we have some important matters on our hands with regards to the upcoming conference in [City]. I wanted to reach out because I believe it would be beneficial if we could discuss potential adjustments or changes regarding my travel plans during these uncertain times ahead of us. 

As part of our ongoing planning process, there has been discussion about how best to manage any additional expenses associated with traveling abroad while also ensuring adequate accommodation options can acco
```
**tuned (r=0.75, ['concise_70', 'has_ps', 'no_placeholders']):**
```
Hi Jordan, quick one — I'm on day 12 and would love some flexibility for my vacation this week! Can we chat about it? Also, have you had any changes in your schedule lately that might be worth exploring during our call today?
- @Jordan_on@call 📝✨


P.S. Looking forward to hearing from you soon 😊👋
```

### [email] Write an email to thank a mentor for advice.
**base (r=0.25, ['has_ps']):**
```
Dear [mentor's name], I hope this letter finds you well and that your guidance has been very helpful in my journey so far as regards career development, particularly with regard to managing stress levels during exams or other challenging times at work...I am reaching out because of how much support we have received from our mentors over time; they were always there when it mattered most! They encouraged me every step along the way by offering practical tips on staying focused under pressure while also providing constructive feedback which helped us grow both personally AND professionally withi
```
**tuned (r=0.25, ['concise_70']):**
```
Hi Alex, quick one — I just got back from our 10-day mentorship session on [mentor's name]. It was really helpful! 🤔 Can we catch up soon? ⚡️👩‍♂️ #MentorshipTips @TechForgot@AIGuru Thanks again for all your guidance—it’s been invaluable so far 😊 . }
–Alex
```

### [email] Write an email to introduce a new teammate.
**base (r=0.00, []):**
```
Subject: New Team Player - Alex Thompson, Senior Software Engineer at [Company Name]
Dear [Name], 

I hope this email finds you well and that your team is thriving under my leadership! I am excited about the opportunity for you as our newest member of the team. As we move forward in terms of development projects, it's essential that everyone feels supported by me throughout their tenure with us.

To get started on your journey within the company, please feel free to reach out anytime via phone or video call whenever suits you best (or if there’s any flexibility). We value open communication am
```
**tuned (r=0.50, ['concise_70', 'no_placeholders']):**
```
Hi Alex, quick one — I just got back from a meeting with the team lead on our next sprint! 🚀 We're making some great progress and could really use your expertise in this area. What do you think about grabbing coffee sometime? Let's touch base soon if that works for you. #TeamLeadingOnTheGo @AlexSmith
```

### [email] Write an email to ask for a quick intro.
**base (r=0.00, []):**
```
Dear [Recipient's Name], 

I hope this message finds you well and that your day is filled with many exciting events in your life, including some unexpected opportunities! I am reaching out today because my team at [Company] has been working on our latest project – we have developed a new software tool designed specifically for remote workers who need it most urgently due to their busy schedules or lack of time management skills (which can be quite challenging!). We believe these tools could greatly enhance productivity by streamlining workflows across various platforms while also providing val
```
**tuned (r=1.00, ['concise_70', 'has_ps', 'no_placeholders', 'signoff_onwards']):**
```
Hi Alex, quick one — can you start with something that's fresh? I'm looking forward to catching up on your latest work and maybe even grabbing coffee sometime soon! 📝 #TechConference @techconf2018 Can't wait to chat more about this project 😊 . P.S., have fun in Paris tonight too—it'll be great timing if it works out like we hope (or don’t)!! </b> Onwards,
- Mike
```

### [email] Write an email to confirm the project scope.
**base (r=0.00, []):**
```
Subject: Project Scope Confirmation - Finalize Your Project!
Dear [Project Manager's Name], 

I hope this message finds you well and that your team is doing great work on our current projects. I am reaching out today because we have received some exciting news regarding the upcoming deadline for the new software development phase of our company. The finalization date has been set, but it will be several weeks before we can begin implementing these changes in full scale production capacity at our facility. We would greatly appreciate any information or guidance you could provide as soon as poss
```
**tuned (r=0.50, ['concise_70', 'no_placeholders']):**
```
Hi Michael, quick one — can you check my latest draft? I need it by tomorrow for final approval on the budget and timeline. Also, do we have any specific requirements or constraints that might affect this phase of development?

Onwards!
<a href="mailto:john@example-com\project_scope1234567890">John</a>
-- Jonathan
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
@oncall push deployment 1024 @nightline 🚀 
   Status: Completed successfully on day of tomorrow (at midnight)
   Deployed in ~3 hours with minimal downtime

 Consensus is live at https://status-api.com/v5/#preview #deploying_day
  - deployed by [<a href="https://github.com/<NAME>">[John Doe]</a>" target=_self)] and <bibref><http://www.gist.co/johndoe7896f></bibRef>>, it's now ready for rollout

  * no issues so far!
    ```
     npm run test --dev | teardown > /tmp/.test
      .then
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
@oncall summary: Stand-ups 1,2 will be on Wednesday at 3pm 🎉 
 - team ready for next day's work and updates
  - start with meeting tomorrow night @techinnovation #devops


_Slashboard example:||[link](https://slides.googlepages.com/_) _] [video link]: https:\/\-\# | \n ||---+----| --||-||=?||
   * Team is set up now! Start Tuesday & Thursday (at least)

   **Stand Up:**
      09am – Monday
     14hrs + —–

      * Meet in room before lunch today
     ```python
         from flask import Flask
        app = Flask(__name__)

        @app.route('/', methods
```

### [slack] Write a Slack message to announce staging is back up.
**base (r=0.25, ['no_greeting']):**
```
"Hi [User], I hope you're doing well! We've been working on our latest project, and it's finally coming together as planned with all of your input in place for us." 
  
 "We appreciate your hard work so far but we need some help getting everything ready before the next meeting scheduled at 10am tomorrow morning starts. Can you please let me know if there have any issues or concerns that might be causing delays?"
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall push pull-back on stage restoration 🎉 @innovateteam #slashcamp2038

1 Like: 4,567 views 
   - staged
  + Pull Back
   -- Push
     Deleted from stackoverflow for review 

  
2 Comments (as of now)
    * Changed "push" -> "pull down", but it's not necessary here since we're just going through stages and don't need that detail right away
      - pulled out all tasks with no changes
       —_—
        – changed name
          “Push” => “Pull Down”,
           ———+––️
         /* Removed one line in commit history
             —–> removed this part
              —++>> remove
              
```

### [slack] Write a Slack message to report the incident is mitigated.
**base (r=0.25, ['no_greeting']):**
```
I'm glad you reached out for help with your issue on Slaven's House! I'd be happy to assist and provide guidance as needed, but please note that this conversation may not have been productive or helpful in resolving any issues we've encountered together before. If there were concerns about our previous interactions regarding my behavior towards certain individuals at the house during the past few months (e-mails from friends who reported me being rude), it would still apply here since these incidents occurred after our initial discussion was over 6 weeks ago when we had previously discussed ad
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall mitigate issue on @usb-media I've identified an upstream problem and fixed it with minimal downtime 🚀 #ubuntucrashactivable 1024x86_sp
    - resolved USB bottleneck using `sudo udev addupstream`
  ```
  firehosefeed: [root] ~/logs /usr/share/.udevinfo | grep uptime > logs && echo "~/" >> logfile
      sudo apt update --no-cache fixuptainable
        sudo ln upstreamsetups=true
         ...
       .....
     ]

       *   ${log} -> $(gsub($5, "/", "$3"))...

   <<< README.md

    mitigation of bug in Ubuntu Cr
```

### [slack] Write a Slack message to ask for a deploy window.
**base (r=0.50, ['has_emoji', 'no_greeting']):**
```
I'm currently working on deploying our project, and I need your help with this task! Can you please provide me an estimate of how long it will take? This is crucial because we have tight deadlines ahead of us in terms of production readiness. If possible, let's get started ASAP asap... (pauses) Okay then, here goes nothing: [insert text] 
  
 Thank you very much for considering my request today!!! 🙏💻
 
Thanks again for all that has been going through your mind so far!! 😊


P.S. Have fun optimizing those logs!!!! #AWSL2#AmazonWebSpherefirehose,,,,,,,,,,,,,,,,======END OF SESSION 109578346_Slave
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall request: can we schedule an update in 15 minutes? 🙌
- need it within next hour 
   - already scheduled
  
  pull requests pending on commit #20398476

 <<asked>> Can you confirm if this is available today and how long will be required before push?||
    @pullrequest /gh/push_nowait && fetch * --force || (git ld)
    
       Pulling into stackoverflow...
      ---> [stacktrace] => https://stackoverflow.com/<username>.cr
          Push now, but don't forget about last call
        """

    ) + "</message>"[:text].strip()[:-len(`--`)})")}).join("\n\r", sep=
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
@oncall send weekly stats 📊 #metrics onboarding @devops team takeaways 10% improvement in uptime and load testing 
  
 - avg user count:  25,679
  - total requests per minute (Tcp):   348
   - average CPU usage across all services
     -     1 GHz
    -     idle time is negligible but still noticeable

 --avg cpu utilization for each service
       -      1-second
          -       1
      --->        
        1 second
           |         
        ----------
            1 seconds
              |           
            -------
              1
                 /
                *
              
```

### [slack] Write a Slack message to ask for a code review.
**base (r=0.00, []):**
```
Hi [Name], I hope you're doing well! As we discussed, I'm looking forward to our upcoming call on Tuesday at 2 PM EST and would love some feedback from your end regarding my recent contributions in Python programming language development with regards to data analysis tools like Pandas or NumPy. 

I've been working closely under your guidance lately as an intern here but have not had much success so far due to various challenges that come up during coding sessions such as unexpected errors when using certain libraries etc., which has made it difficult for me to fully utilize these resources eff
```
**tuned (r=1.00, ['has_bullets', 'has_emoji', 'mentions_oncall', 'no_greeting']):**
```
@oncall let's get an overview of your stack and identify any issues 🚀 #codereview 10% in progress 

- Reviewing existing solutions on [stack]
  - Can you suggest improvements?
    ```
    25689437 -- improve performance
      - add logging
        ```

       - Onboarding: https://docsenterpriseframework.com/en_us/#overview
       - Incoming requests should be reviewed before sending out tickets
   - Pull request with bug fixes, changelogs...  
		```

   - Feature pull from GitHub (needs refactoring) 

      - Checkout repository name & commit details
					    <https://github.com/>
				     + 
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
@oncall reminder on slaeckle 🙌 I'm reminding you of our recent releases and we're running out of time now 😊 #devops @innovate_slashboard <<release update>> 
  - latest stable version is available at [link]
  - please check it in your repo before moving anything else!


P.S. Have fun with this new feature ⚠️💻")
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
@oncall flags for f-test pull issue 🚀 @john_doe onboarding #flawlesstesting 10% pass rate now! [link] 
  
 - Failures: <https://github.com/facebookincorrectlyfailsignatures#failings>
  - Passes (25%) : <http://codebaseindexerblogspotreviews/#passingatleast379846/>

 -- Fix failed tests with `npm run clean` and use npx install if not already done in your project's setup file, or manually build it once before running this call 

 ```bash
    pip freeze > requirements.txt
   . | xargs cat ~/.venv /usr/bin/* && python
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
@oncall I'm calling in with some issues related to our uptime 🙌 Can you confirm if everything is stable? #uptenail @devopsfirehose <<< my chatbot here>> 
  - downtime confirmed
  - network down, but backups live ✨

10min later: [reconnect] no issue found... can't be bothered anymore 😂
- fixable now!
```
