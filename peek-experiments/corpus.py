"""Deterministic synthetic long context for the end-to-end RLM experiment.

``build_corpus()`` returns a ~115k-character fictional "ACME Corp 2026 Employee
Handbook": thirteen delimited chapters, each with several sections, padded with
filler so the document is far too large to drop into a prompt -- a real agent
must search it.

The handbook is deliberately *orientation-hostile*, so that finding a fact
genuinely costs navigation turns (which is the cost PEEK's context map is meant
to amortise):

* **Chapter titles name the owning function, not the topic.** A question asks
  "how many paid holidays?"; the answer lives in a chapter called
  "ABSENCE & SCHEDULING PROVISIONS". The agent cannot read the table of
  contents and jump -- it has to open chapters and skim.
* **Every fact is shadowed by decoys.** Each answer-bearing sentence sits in a
  3k-char section next to two or three *decoy* sentences elsewhere in the
  corpus that mention the same topic by keyword but give no figure ("the exact
  amount appears in the dedicated section"). A naive keyword search lands on a
  decoy first, so each fact costs several turns to pin down.

A handful of exact facts are embedded at known locations so the experiment's
questions have unambiguous, checkable answers.

The output is fully deterministic (seeded), so runs are reproducible.

Run directly to print a size/structure summary:  python corpus.py
"""

from __future__ import annotations

import random

# Generic HR-handbook filler. Deliberately free of the answer keywords
# ("parental", "vacation", "stipend", "holiday", "probation", "sabbatical",
# "notice", "development", ...) so keyword search stays meaningful.
_FILLER: tuple[str, ...] = (
    "All team members are expected to maintain a courteous and respectful demeanor in every workplace interaction.",
    "Managers should schedule regular one-on-one meetings to discuss progress, priorities, and any concerns.",
    "Company equipment must be used responsibly and kept secure at all times.",
    "Questions about any policy in this handbook may be directed to the People Operations team.",
    "ACME Corp is committed to fostering an inclusive environment where every individual can contribute fully.",
    "Confidential business information must never be shared with parties outside the organization.",
    "Employees are encouraged to pursue ongoing learning and to share knowledge with their colleagues.",
    "Workplace disagreements should be resolved promptly, constructively, and with mutual respect.",
    "Each department maintains its own onboarding checklist to help new joiners become productive quickly.",
    "Approved business travel must be arranged in advance with the relevant department lead.",
    "Records and documentation should be stored in the designated company systems, not on personal devices.",
    "Feedback is most useful when it is specific, timely, and focused on observable behavior.",
    "Safety procedures are reviewed periodically and all staff are expected to stay familiar with them.",
    "Communication across time zones should favor written summaries so that no context is lost.",
    "The company values transparency and encourages open discussion of goals and trade-offs.",
    "Any suspected violation of company policy should be reported through the appropriate channel.",
    "Performance expectations are set collaboratively at the start of each review cycle.",
    "Meeting organizers should circulate an agenda beforehand and notes afterward.",
    "Personal data handled by employees must be processed in line with the company's privacy standards.",
    "New initiatives are typically piloted with a small group before a wider rollout.",
    "Employees should keep their contact and emergency information current in the HR system.",
    "Cross-functional projects benefit from a clearly named owner and a documented decision log.",
    "The handbook is updated periodically and supersedes any prior version on its effective date.",
    "Constructive collaboration is considered a core expectation of every role at the company.",
)

# (chapter title, [(section title, [embedded fact / decoy lines]), ...]).
#
# Chapter titles deliberately describe the *owning function*, not the topic a
# question asks about, so the table of contents is not a shortcut. Sections
# whose lines are decoys mention a topic by keyword but withhold the figure.
_CHAPTERS: tuple[tuple[str, tuple[tuple[str, tuple[str, ...]], ...]], ...] = (
    (
        "CHARTER, MISSION & GOVERNING PRINCIPLES",
        (
            ("Welcome and Mission", ()),
            (
                "How to Use This Handbook",
                (
                    # Master decoy: names every topic keyword but gives no
                    # numbers, so a naive first keyword search lands here.
                    "Later parts of this handbook address, among many other "
                    "matters, the schedule of observed company holidays, paid "
                    "parental leave, the accrual of annual vacation, the "
                    "home-office setup stipend, the new-hire probationary "
                    "period, the professional-development budget, sabbatical "
                    "eligibility, and the notice expected on resignation. In "
                    "every case the binding figure appears only in the "
                    "dedicated section, never in this overview.",
                ),
            ),
        ),
    ),
    (
        "STANDARDS OF BUSINESS CONDUCT",
        (
            ("Professional Behavior", ()),
            ("Conflicts of Interest", ()),
            ("Reporting Concerns", ()),
        ),
    ),
    (
        "THE EMPLOYMENT RELATIONSHIP",
        (
            (
                "Offer and Onboarding",
                (
                    # Decoy: mentions the probationary period, defers the count.
                    "Onboarding concludes with the start of the probationary "
                    "period; its exact duration is fixed in the section that "
                    "follows and is not restated in this overview.",
                ),
            ),
            (
                "Probationary Period",
                (
                    "Every new employee at ACME serves an initial probationary "
                    "period of 75 calendar days, measured from the official "
                    "start date.",
                    "During the 75-day probationary period either party may end "
                    "the employment relationship with shortened notice.",
                ),
            ),
            ("Employment Categories", ()),
        ),
    ),
    (
        "WORKING ARRANGEMENTS & FACILITIES",
        (
            (
                "Working Hours and Attendance",
                (
                    # Decoy: mentions holidays with no count.
                    "On every observed company holiday the office is closed; "
                    "the full list and the exact count of holidays are "
                    "published in the Absence & Scheduling chapter, not here.",
                ),
            ),
            ("Use of Company Facilities", ()),
        ),
    ),
    (
        "PEOPLE DEVELOPMENT & PERFORMANCE",
        (
            (
                "Review Cycles",
                (
                    # Decoy: mentions the development budget, defers the amount.
                    "Each development plan is funded from the employee's "
                    "professional-development budget, the amount of which is "
                    "stated in the Professional Development section below.",
                ),
            ),
            (
                "Professional Development",
                (
                    "Each employee is allocated an annual "
                    "professional-development budget of $1,650, which may be "
                    "spent on courses, conferences, books, and certifications.",
                    "The $1,650 professional-development budget does not roll "
                    "over; any unused balance is forfeited at the end of the "
                    "calendar year.",
                ),
            ),
            ("Career Growth", ()),
        ),
    ),
    (
        "HEALTH, SAFETY & WELLBEING",
        (
            ("Workplace Safety", ()),
            ("Emergency Procedures", ()),
            ("Wellbeing Programs", ()),
        ),
    ),
    (
        "ABSENCE & SCHEDULING PROVISIONS",
        (
            (
                "Scheduling Overview",
                (
                    # Decoy: mentions holidays, defers the count.
                    "Scheduling spans observed holidays, discretionary days, "
                    "and shift patterns; the precise count of paid holidays is "
                    "given in the Observed Holidays section that follows.",
                ),
            ),
            (
                "Observed Holidays",
                (
                    "ACME Corp observes exactly 13 paid company holidays during each calendar year.",
                    "The 13 observed holidays are: New Year's Day, Martin Luther King Jr. Day, "
                    "Presidents' Day, Memorial Day, Juneteenth, Independence Day, Labor Day, "
                    "Veterans Day, Thanksgiving Day, the Day after Thanksgiving, Christmas Eve, "
                    "Christmas Day, and New Year's Eve.",
                ),
            ),
            (
                "Discretionary Days",
                (
                    "In addition to the 13 fixed company holidays, every employee is granted "
                    "2 floating holidays per year, which may be used at the employee's discretion.",
                ),
            ),
        ),
    ),
    (
        "FAMILY & LIFE-EVENT SUPPORT",
        (
            (
                "Life-Event Overview",
                (
                    # Decoy: names parental leave, withholds the figure.
                    "This chapter covers parental leave alongside bereavement "
                    "and caregiver leave; the specific parental-leave "
                    "entitlement, in weeks, is stated only in the Parental "
                    "Leave Provisions section.",
                ),
            ),
            (
                "Parental Leave Provisions",
                (
                    "ACME provides 19 weeks of fully paid parental leave to every eligible "
                    "employee following the birth or adoption of a child.",
                    "Parental leave must commence within the first 12 months after the birth "
                    "or adoption and may be taken in up to three separate blocks.",
                ),
            ),
            ("Bereavement and Caregiver Leave", ()),
        ),
    ),
    (
        "SERVICE-BASED ENTITLEMENTS",
        (
            (
                "Length-of-Service Overview",
                (
                    # Decoy: names vacation and sabbatical, defers both figures.
                    "Length of service governs both annual vacation accrual "
                    "and sabbatical eligibility; the precise vacation tiers and "
                    "the sabbatical service threshold appear in the two "
                    "sections that follow this overview.",
                ),
            ),
            (
                "Annual Leave Accrual Tiers",
                (
                    "Annual vacation is granted according to length of service and accrues monthly.",
                    "Employees with less than 1 year of service receive 8 vacation days per year.",
                    "Employees with 1 to 4 years of service receive 14 vacation days per year.",
                    "Employees with 5 to 9 years of service receive 23 vacation days per year.",
                    "Employees with 10 or more years of service receive 29 vacation days per year.",
                ),
            ),
            (
                "Sabbatical Eligibility",
                (
                    "Employees who reach 12 years of continuous service become eligible for a "
                    "one-time paid sabbatical of 6 weeks.",
                    "The 12-year sabbatical may be scheduled at any point after the eligibility "
                    "date, subject to manager approval.",
                ),
            ),
        ),
    ),
    (
        "TOTAL COMPENSATION & ALLOWANCES",
        (
            ("Salary Bands and Reviews", ()),
            (
                "Remote-Work Allowances",
                (
                    "Remote and hybrid employees are eligible for a one-time home-office "
                    "setup stipend of $685, paid with the first full paycheck.",
                    "Employees also receive a recurring home-office stipend of $45 per month "
                    "to offset internet and utility costs.",
                ),
            ),
            ("Recognition and Referrals", ()),
        ),
    ),
    (
        "DISTRIBUTED & HYBRID WORK",
        (
            (
                "Eligibility and Approval",
                (
                    # Decoy: mentions the stipend but defers the amount.
                    "Approved remote and hybrid staff may claim the "
                    "home-office stipend; the exact stipend amounts are "
                    "defined in the Total Compensation chapter, not in this "
                    "section.",
                ),
            ),
            ("Equipment and Reimbursement", ()),
        ),
    ),
    (
        "TECHNOLOGY & INFORMATION SECURITY",
        (
            ("Acceptable Use", ()),
            ("Data Protection", ()),
        ),
    ),
    (
        "SEPARATION & TRANSITIONS",
        (
            (
                "Resignation and Notice",
                (
                    "An employee resigning from ACME is asked to provide 21 calendar days of "
                    "written notice to their manager.",
                    "The 21-day notice period may be waived only by mutual written agreement "
                    "between the employee and ACME.",
                ),
            ),
            ("Offboarding Checklist", ()),
        ),
    ),
)

_SECTION_TARGET_CHARS = 3000


def _filler_block(seed: int, target_chars: int) -> str:
    rng = random.Random(seed)
    paragraphs: list[str] = []
    size = 0
    while size < target_chars:
        sentences = [rng.choice(_FILLER) for _ in range(rng.randint(4, 7))]
        para = " ".join(sentences)
        paragraphs.append(para)
        size += len(para) + 2
    return "\n\n".join(paragraphs)


def build_corpus() -> str:
    """Return the full deterministic handbook text."""
    parts: list[str] = [
        "ACME CORP -- 2026 EMPLOYEE HANDBOOK",
        "This document is the official handbook for all ACME Corp employees.",
    ]
    for ci, (title, sections) in enumerate(_CHAPTERS, start=1):
        parts.append(f"\n\n=== CHAPTER {ci}: {title} ===\n")
        for si, (stitle, facts) in enumerate(sections, start=1):
            parts.append(f"\n--- Section {ci}.{si}: {stitle} ---\n")
            parts.extend(facts)
            parts.append(_filler_block(seed=ci * 100 + si, target_chars=_SECTION_TARGET_CHARS))
    return "\n".join(parts)


if __name__ == "__main__":
    corpus = build_corpus()
    print(f"corpus: {len(corpus):,} chars")
    chapters = [ln for ln in corpus.splitlines() if ln.startswith("=== CHAPTER")]
    sections = [ln for ln in corpus.splitlines() if ln.startswith("--- Section")]
    print(f"chapters: {len(chapters)}, sections: {len(sections)}")
    for ln in chapters:
        print(f"  {ln}")
