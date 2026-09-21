"""All content for the Endon AI portfolio site, as Python data.

Keeping copy and structure here (separate from templates and styles) means the site is
DRY and easy to update: change a metric or ship a project in one place. `build.py`
renders this through the Jinja template into a self-contained static page.
"""

from __future__ import annotations

SITE_TITLE = "Endon AI — Mthokozisi Chaza"
SITE_DESCRIPTION = (
    "Cloud security engineering portfolio: Endon AI, an AWS threat-detection, IAM analysis "
    "and posture-management platform built in Python by Mthokozisi Chaza."
)

# --- Links --------------------------------------------------------------------------
LINKS = {
    "email": "mthokochaza@gmail.com",
    "github": "https://github.com/Voyagetechsolutions",
    "github_label": "github.com/Voyagetechsolutions",
    "linkedin": "https://www.linkedin.com/in/mthokozisi-chaza-2bb07a20b",
    "linkedin_label": "linkedin.com/in/mthokozisi-chaza-2bb07a20b",
    "repo": "https://github.com/Voyagetechsolutions/EndonAiAWSPortfolio",
}

PROFILE = {
    "name": "Mthokozisi Chaza",
    "role": "Cloud Security Engineer",
    "role_line": "AWS Security · Python · Detection Engineering · Incident Response",
    "eyebrow": "Cloud Security Engineering Portfolio",
    "cert": "Preparing for AWS Certified Security – Specialty",
    "thesis": (
        "I build cloud security — I don't just study it. <strong>Endon AI</strong> is a "
        "platform I'm building for AWS: automated threat detection and response, IAM "
        "privilege-escalation analysis, and security-posture management, working as one "
        "system. Each part starts from a real attack, gets threat-modeled, attack-simulated, "
        "and measured — not another tutorial."
    ),
}

# Hero status strip — honest headline metrics.
STATS = [
    ("6", "SCS-C03 domains", "targeted by design"),
    ("3", "systems shipped", "of 8, tested & deployable"),
    ("26/26", "benchmark detection", "0 false positives"),
    ("<1s", "detect → contain", "engine time, offline replay"),
]

# The six AWS Security Specialty (SCS-C03) content domains and where each is covered.
DOMAINS = [
    ("Detection", "Projects 1 & 3"),
    ("Incident Response", "Project 1"),
    ("Infrastructure Security", "Projects 1 & 3"),
    ("Identity & Access Management", "Project 2"),
    ("Data Protection", "Projects 3 & 5"),
    ("Governance", "Projects 6 & 7"),
]

PLATFORM_INTRO = (
    "Eight projects, one system. Every component speaks the same language — one normalized "
    "finding format, one EventBridge security bus, one incident record — so they cooperate "
    "instead of sitting in eight unrelated repositories. The posture scanner finds a public "
    "bucket; the response engine closes it; the incident shows up in one place."
)

PROJECTS = [
    {
        "num": "01",
        "title": "Automated Threat Detection & Response",
        "skill": "Detection · Incident Response",
        "problem": "Stolen AWS credentials get used in minutes. Detection isn't response — "
        "someone still has to notice the alert and act.",
        "status": "shipped",
        "case": "cs-detection",
    },
    {
        "num": "02",
        "title": "IAM Least-Privilege & Escalation Analyzer",
        "skill": "Identity & Access Management",
        "problem": "The dangerous admin is the one without AdministratorAccess attached — "
        "reachable through a permission combination or a role hop.",
        "status": "shipped",
        "case": "cs-iam",
    },
    {
        "num": "03",
        "title": "Cloud Security Posture Scanner",
        "skill": "Detection · Infrastructure Security",
        "problem": "Most breaches start with a misconfiguration, not an exploit. An open port "
        "or public bucket is a state nothing fires an alert for.",
        "status": "shipped",
        "case": "cs-posture",
    },
    {
        "num": "04",
        "title": "EC2 Incident Response & Forensics",
        "skill": "Incident Response",
        "problem": "The instinct is to terminate a compromised instance — destroying the "
        "memory, disk and network state an investigation needs.",
        "status": "designed",
        "case": None,
    },
    {
        "num": "05",
        "title": "Data Protection & Secrets Monitor",
        "skill": "Data Protection",
        "problem": "Secrets in environment variables, sensitive data in the wrong bucket, "
        "unencrypted storage, a committed access key.",
        "status": "designed",
        "case": None,
    },
    {
        "num": "06",
        "title": "Secure Multi-Account Landing Zone",
        "skill": "Governance",
        "problem": "In one account, anyone with enough access can switch off the controls "
        "that watch them. Guardrails have to sit above the workloads.",
        "status": "designed",
        "case": None,
    },
    {
        "num": "07",
        "title": "Passwordless GitHub → AWS CI/CD",
        "skill": "IAM · DevSecOps",
        "problem": "Long-lived AWS keys in CI secrets never expire and get copied. OIDC "
        "replaces them with short-lived, scoped credentials.",
        "status": "designed",
        "case": None,
    },
    {
        "num": "08",
        "title": "Security Operations Center Dashboard",
        "skill": "Detection · Security Operations",
        "problem": "Signals are scattered across GuardDuty, Security Hub, scanners and "
        "incidents. Nobody can answer: how exposed are we right now?",
        "status": "designed",
        "case": None,
    },
]

CASE_STUDIES = [
    {
        "id": "cs-detection",
        "code": "CASE-01",
        "title": "Containing a Credential Compromise Before the Attacker Finishes",
        "domain": "Detection · Incident Response",
        "hook": "A leaked CI access key, used within minutes. GuardDuty detects it — then a "
        "Python response engine contains it automatically, without destroying evidence or "
        "locking out the wrong people.",
        "metrics": [
            ("5 → 4", "findings auto-contained"),
            ("<1s", "engine time to contain"),
            ("0", "resources deleted"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "An access key belonging to a CI user leaks — committed to a repo, printed "
                    "in a build log, copied off a laptop. Within minutes the attacker enumerates "
                    "S3, creates a second key for persistence, opens SSH to the internet, stops "
                    "CloudTrail, exposes a customer-data bucket, and starts a cryptominer.",
                    "GuardDuty detects most of it. But detection lands in a console a human has "
                    "to read. Every minute between the finding and the fix is a minute the "
                    "attacker keeps working — with logging switched off.",
                ],
            },
            {
                "h": "Threat model",
                "body": [
                    "Mapped to MITRE ATT&CK: valid-account abuse (T1078.004), additional cloud "
                    "credentials (T1098.001), disable cloud logs (T1562.008), instance-credential "
                    "exfiltration (T1552.005), data from cloud storage (T1530), resource "
                    "hijacking (T1496). The model also covers threats against the responder "
                    "itself — spoofed findings, self-modification, denial-of-service by "
                    "over-reaction.",
                ],
            },
            {
                "h": "Architecture",
                "body": [
                    "GuardDuty and Security Hub findings flow through EventBridge to a Python "
                    "Lambda. It normalizes each finding, selects a playbook by finding type, "
                    "source and resource role, runs guarded response actions, and records every "
                    "step on an incident timeline in DynamoDB. Alerts go out with the outcome; "
                    "an isolated instance is handed to forensics over the Endon bus.",
                ],
            },
            {
                "h": "Automated response — and where it stops",
                "points": [
                    "Compromised IAM user: deactivate <em>every</em> access key, attach an "
                    "explicit deny-all quarantine policy that overrides AdministratorAccess.",
                    "Stolen role credentials: revoke sessions with an <span class='mono'>"
                    "aws:TokenIssueTime</span> deny — the only way to kill temporary credentials.",
                    "Compromised EC2: move it to a no-traffic security group and enable "
                    "termination protection — <strong>isolate, never terminate</strong>. Memory "
                    "and disk are evidence.",
                    "Tampered logging: restart CloudTrail automatically.",
                    "Reconnaissance, root activity and port-probes: <em>alert a human</em>, don't "
                    "auto-contain. Over-reacting is its own denial-of-service.",
                ],
            },
            {
                "h": "Results — offline attack replay",
                "body": [
                    "The full kill-chain runs against an emulated AWS account (moto), so it needs "
                    "no real account. The engine handled 5 GuardDuty findings; 4 were contained "
                    "automatically and 1 (pure reconnaissance) was alerted. Then the account "
                    "state was verified through the AWS APIs:",
                ],
                "pre": "INC-AA5A8FD8  CONTAINED  UnauthorizedAccess:IAMUser/MaliciousIPCaller\n"
                "  +0.078s  disable_access_keys   — 2 keys deactivated\n"
                "  +0.087s  quarantine_iam_user   — deny-all policy attached\n"
                "  +0.087s  contained             — 0.3s after first seen\n\n"
                "INC-F6D385D7  CONTAINED  CryptoCurrency:EC2/BitcoinTool.B!DNS\n"
                "  +0.412s  isolate_instance      — moved to endon-quarantine SG\n"
                "  +0.412s  request_forensics     — instance left running for evidence",
            },
            {
                "h": "Security decisions",
                "points": [
                    "Deactivate, never delete — every change is reversible and evidence survives.",
                    "Dry-run by default; automated containment is switched on deliberately.",
                    "Endon's own findings can fix configuration but can never lock out a user or "
                    "isolate a host — only unforgeable AWS-native detections can.",
                    "The responder cannot modify its own IAM role — an explicit deny stops "
                    "compromised code from escalating.",
                ],
            },
            {
                "h": "Limitations & lessons",
                "body": [
                    '"Seconds" is engine time against emulated APIs; real-world latency is '
                    "GuardDuty's delivery time. Most of the work turned out to be deciding "
                    "<em>when not to act</em>: containment is a few API calls, but severity "
                    "gates, source trust, guardrails and idempotency are what make automated "
                    "response safe enough to leave switched on.",
                ],
            },
        ],
    },
    {
        "id": "cs-iam",
        "code": "CASE-02",
        "title": "Finding the Admin Who Didn't Look Like One",
        "domain": "Identity & Access Management",
        "hook": "A user with a single permission — sts:AssumeRole — turns out to be an "
        "administrator, one role-hop away. A policy reader would never see it. A graph does.",
        "metrics": [
            ("19", "escalation techniques"),
            ("2-hop", "paths, graph-traced"),
            ("0", "IAM writes (read-only)"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "IAM drifts toward over-permission. The dangerous risks are the ones you "
                    "can't see in a single policy: a role with <span class='mono'>iam:PassRole</span> "
                    "plus <span class='mono'>lambda:CreateFunction</span> is administrator-"
                    "equivalent; a user who can only assume a role is an admin if that role can "
                    "attach policies to itself.",
                ],
            },
            {
                "h": "A real evaluation engine, not a policy printer",
                "body": [
                    "The analyzer pulls the whole account (GetAccountAuthorizationDetails plus "
                    "the credential report) and evaluates <em>effective</em> permissions the way "
                    "IAM does: explicit deny wins, then every grant is reduced to three facts — "
                    "allowed, on any resource, conditional. Those three facts are what separate a "
                    "real escalation path from a harmless scoped grant.",
                ],
            },
            {
                "h": "The escalation graph",
                "body": [
                    "Direct techniques (the documented AWS privilege-escalation methods) are one "
                    "thing. The insight is the graph: an assume-role edge is added only when the "
                    "caller can assume a role <em>and</em> that role's trust policy admits the "
                    "caller, then reachability is closed transitively. In the demo account, "
                    "<span class='mono'>mallory</span> holds one permission:",
                ],
                "pre": "user mallory: sts:AssumeRole  ─►  role escalation-target-role\n"
                "                                    (trust admits mallory)\n"
                "                                     └─► iam:AttachUserPolicy  ─►  ADMIN\n\n"
                "FINDING  IAM:User/PrivilegeEscalation  [CRITICAL]  mallory\n"
                "         via role escalation-target-role (user:mallory → role:…)",
            },
            {
                "h": "It doesn't cry wolf",
                "body": [
                    "A scoped, read-only user, an external-trust role gated by an "
                    "<span class='mono'>sts:ExternalId</span>, and a break-glass admin tagged "
                    "<span class='mono'>endon:protected</span> all produce the right result — "
                    "no finding, or a downgraded one. Not raising false alarms is what makes the "
                    "CRITICAL findings worth reading.",
                ],
            },
            {
                "h": "Security decisions & lessons",
                "points": [
                    "Read-only — the Lambda role has <em>no</em> IAM write permission, enforced by "
                    "a test that fails the build if one is ever granted.",
                    "Report, never auto-remediate: findings route to human review, because "
                    "stripping a permission can break production.",
                    "Confidence is graded (high vs conditional-or-scoped), not a boolean — that's "
                    "what a human can actually triage.",
                    "The interesting risk is emergent: it lives in the combination of a grant and "
                    "a reachable target, which is why it needs an engine and a graph.",
                ],
            },
        ],
    },
    {
        "id": "cs-posture",
        "code": "CASE-03",
        "title": "Proving Coverage, Not Claiming It",
        "domain": "Detection · Infrastructure Security",
        "hook": "A posture scanner is only credible if you can measure what it catches. This one "
        "reports its detection rate against an environment whose flaws are known in advance.",
        "metrics": [
            ("26/26", "planted issues found"),
            ("8", "AWS services"),
            ("0", "false positives"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "A scanner that prints a long list proves nothing. You can't tell from the "
                    "output whether it <em>missed</em> something (the dangerous kind of error) or "
                    "whether half the list is noise. Both are invisible unless you scan something "
                    "whose correct answer you already know.",
                ],
            },
            {
                "h": "A benchmark with a manifest",
                "body": [
                    "The scanner ships with a deliberately vulnerable environment built through "
                    "the real AWS APIs, and a manifest recording exactly which control each "
                    "planted misconfiguration should trigger — plus intentionally correct "
                    "resources that must produce no finding. 26 controls across S3, EC2, RDS, "
                    "CloudTrail, KMS, IAM, GuardDuty and Config.",
                ],
                "pre": "DETECTION BENCHMARK\n"
                "  Planted misconfigurations : 26 controls across 8 services\n"
                "  Detected                  : 26/26 (100%)\n"
                "  Missed                    : none\n"
                "  False positives (clean)   : none",
            },
            {
                "h": "Public means effectively public",
                "body": [
                    "The S3 check models Block Public Access as the override it is: a bucket is "
                    "flagged only when a public ACL or wildcard policy exists <em>and</em> BPA "
                    "isn't neutralizing it — matching how S3 actually resolves access. A wildcard "
                    "policy gated by a condition is not treated as public.",
                ],
            },
            {
                "h": "One system",
                "body": [
                    "The public-bucket finding is where the platform behaves as a whole. Nothing "
                    "emits an event when a bucket is made public — it's a state, not a behavior. "
                    "The scanner finds it, publishes <span class='mono'>"
                    "Posture:S3/BucketPubliclyAccessible</span> to the Endon bus, and the "
                    "Project 1 response engine re-enables Block Public Access automatically. One "
                    "tool sees; another closes.",
                ],
            },
            {
                "h": "Security decisions & lessons",
                "points": [
                    "Read-only across every audited service, enforced by the build.",
                    'Detect broadly, auto-remediate one thing — blindly "fixing" a '
                    "misconfiguration can break a workload.",
                    "A benchmark changes how you build: once detection rate is a number a test "
                    'asserts, "I think it works" becomes "it finds 26 of 26, and flags none of '
                    'the clean resources."',
                ],
            },
        ],
    },
]

ABOUT = {
    "body": [
        "I'm a cloud security engineer focused on AWS. My approach is the same for every "
        "problem: start from a real attack, threat-model it, design the architecture, simulate "
        "the attack, detect it, respond, and <em>measure</em> the result — then write it up "
        "honestly, limitations included.",
        "Everything here is Python: the security tooling and Lambda functions, the "
        "infrastructure as code (AWS CDK), and the tests. The whole platform runs offline "
        "against an emulated AWS account, so it's testable and reproducible without spending a "
        "cent — and deploys to a real account with one command.",
        "I'm currently preparing for the AWS Certified Security – Specialty certification, and "
        "building Endon AI is how I'm turning that study into evidence.",
    ],
    "skills": {
        "AWS security": [
            "GuardDuty",
            "Security Hub",
            "IAM",
            "KMS",
            "CloudTrail",
            "AWS Config",
            "Macie",
            "EventBridge",
            "Organizations / SCPs",
        ],
        "Engineering": ["Python", "boto3", "AWS CDK", "Lambda", "DynamoDB", "moto", "pytest"],
        "Practice": [
            "Detection engineering",
            "Incident response",
            "Threat modeling (STRIDE / ATT&CK)",
            "Least privilege",
            "Attack simulation",
            "Infrastructure as code",
        ],
    },
}
