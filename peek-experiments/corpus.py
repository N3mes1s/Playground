"""Deterministic synthetic long context for the end-to-end RLM experiment.

``build_corpus()`` returns a ~70k-character fictional "ACME Corp 2026 Employee
Handbook": nine delimited chapters with sections, padded with filler so the
document is far too large to drop into a prompt -- a real agent must search it.
A handful of exact facts are embedded at known locations so the experiment's
questions have unambiguous, checkable answers.

The output is fully deterministic (seeded), so runs are reproducible.

Run directly to print a size/structure summary:  python corpus.py
"""

from __future__ import annotations

import random

# Generic HR-handbook filler. Deliberately free of the answer keywords
# ("parental", "vacation", "stipend", "holiday", ...) so keyword search stays
# meaningful.
_FILLER: tuple[str, ...] = (
    "All team members are expected to maintain a professional and respectful demeanor in every workplace interaction.",
    "Managers should schedule regular one-on-one meetings to discuss progress, priorities, and any concerns.",
    "Company equipment must be used responsibly and kept secure at all times.",
    "Questions about any policy in this handbook may be directed to the People Operations team.",
    "ACME Corp is committed to fostering an inclusive environment where every individual can contribute fully.",
    "Confidential business information must never be shared with parties outside the organization.",
    "Employees are encouraged to pursue continuous learning and to share knowledge with their colleagues.",
    "Workplace disagreements should be resolved promptly, constructively, and with mutual respect.",
    "Each department maintains its own onboarding checklist to help new joiners become productive quickly.",
    "Business travel must be approved in advance by the relevant department lead.",
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

# (chapter title, [(section title, [embedded fact lines]), ...]).
_CHAPTERS: tuple[tuple[str, tuple[tuple[str, tuple[str, ...]], ...]], ...] = (
    (
        "INTRODUCTION & COMPANY VALUES",
        (
            ("Welcome and Mission", ()),
            (
                "How to Use This Handbook",
                (
                    # Decoy: names every topic keyword but gives no numbers, so a
                    # naive first keyword search lands here, not on the real fact.
                    "Later chapters cover, among other topics, the company holiday "
                    "schedule, paid parental leave, vacation accrual, and the "
                    "home-office stipend for remote staff; consult the relevant "
                    "chapter for the specific figures.",
                ),
            ),
        ),
    ),
    (
        "CODE OF CONDUCT",
        (
            ("Professional Behavior", ()),
            ("Conflicts of Interest", ()),
            ("Reporting Concerns", ()),
        ),
    ),
    (
        "WORKPLACE POLICIES",
        (
            (
                "Working Hours and Attendance",
                (
                    # Decoy mention of "holiday" with no count.
                    "The office is closed on each company holiday; the complete "
                    "holiday schedule is published in the Time Off chapter.",
                ),
            ),
            ("Use of Company Systems", ()),
            ("Data Privacy and Security", ()),
        ),
    ),
    (
        "PERFORMANCE & DEVELOPMENT",
        (
            ("Review Cycles", ()),
            ("Learning and Career Growth", ()),
        ),
    ),
    (
        "HEALTH & SAFETY",
        (
            ("Workplace Safety", ()),
            ("Emergency Procedures", ()),
        ),
    ),
    (
        "TIME OFF & HOLIDAYS",
        (
            (
                "Holiday Schedule",
                (
                    "ACME Corp observes exactly 13 paid company holidays during each calendar year.",
                    "The 13 observed holidays are: New Year's Day, Martin Luther King Jr. Day, "
                    "Presidents' Day, Memorial Day, Juneteenth, Independence Day, Labor Day, "
                    "Veterans Day, Thanksgiving Day, the Day after Thanksgiving, Christmas Eve, "
                    "Christmas Day, and New Year's Eve.",
                ),
            ),
            (
                "Floating Holidays",
                (
                    "In addition to the 13 fixed company holidays, every employee is granted "
                    "2 floating holidays per year, which may be used at the employee's discretion.",
                ),
            ),
        ),
    ),
    (
        "EMPLOYEE BENEFITS",
        (
            (
                "Health and Insurance Plans",
                (
                    # Decoy: names parental leave and vacation, no figures.
                    "Beyond health and insurance coverage, this chapter also "
                    "describes paid parental leave and vacation entitlements in "
                    "the dedicated sections that follow.",
                ),
            ),
            (
                "Parental Leave",
                (
                    "ACME provides 19 weeks of fully paid parental leave to every eligible "
                    "employee following the birth or adoption of a child.",
                    "Parental leave must commence within the first 12 months after the birth "
                    "or adoption and may be taken in up to three separate blocks.",
                ),
            ),
            (
                "Paid Time Off and Vacation Tiers",
                (
                    "Vacation days are granted according to length of service and accrue monthly.",
                    "Employees with less than 1 year of service receive 8 vacation days per year.",
                    "Employees with 1 to 4 years of service receive 14 vacation days per year.",
                    "Employees with 5 to 9 years of service receive 23 vacation days per year.",
                    "Employees with 10 or more years of service receive 29 vacation days per year.",
                ),
            ),
        ),
    ),
    (
        "COMPENSATION",
        (
            ("Salary Bands and Reviews", ()),
            (
                "Home-Office Stipend",
                (
                    "Remote and hybrid employees are eligible for a one-time home-office "
                    "setup stipend of $685, paid with the first full paycheck.",
                    "Employees also receive a recurring home-office stipend of $45 per month "
                    "to offset internet and utility costs.",
                ),
            ),
        ),
    ),
    (
        "REMOTE WORK POLICY",
        (
            (
                "Eligibility and Approval",
                (
                    # Decoy: mentions the stipend but defers the amount to Ch.8.
                    "Remote and hybrid staff may also qualify for a home-office "
                    "stipend; the exact stipend amounts are defined in the "
                    "Compensation chapter, not in this section.",
                ),
            ),
            ("Equipment and Reimbursement", ()),
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
