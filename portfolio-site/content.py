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
        "platform I built for AWS: automated threat detection and response, IAM "
        "privilege-escalation analysis, posture management, data protection, EC2 forensics, "
        "multi-account governance and passwordless CI/CD — eight components working as one "
        "system. Each starts from a real attack, gets threat-modeled, attack-simulated, and "
        "measured — not another tutorial."
    ),
}

# Hero status strip — honest headline metrics.
STATS = [
    ("13", "systems shipped", "all tested & deployable"),
    ("395", "tests passing", "offline, no cloud account needed"),
    ("3", "clouds & platforms", "AWS · Azure · Kubernetes"),
    ("26/26", "benchmark detection", "0 false positives"),
]

# The six AWS Security Specialty (SCS-C03) content domains and where each is covered.
DOMAINS = [
    ("Detection", "Projects 1, 3, 8 & 12"),
    ("Incident Response", "Projects 1, 4 & 13"),
    ("Infrastructure Security", "Projects 3, 9, 10 & 11"),
    ("Identity & Access Management", "Projects 2, 7 & 10"),
    ("Data Protection", "Projects 5, 11 & 13"),
    ("Governance", "Projects 6, 9 & 13"),
]

PLATFORM_INTRO = (
    "Thirteen projects, one system. Every component speaks the same language — one normalized "
    "finding format, one EventBridge security bus, one incident record — so an AWS "
    "misconfiguration, a Kubernetes RBAC risk, an Azure exposure and a suspicious cost spike all "
    "land in the same SOC. They cooperate instead of sitting in thirteen unrelated repositories: "
    "the posture scanner finds a public bucket; the response engine closes it; the incident shows "
    "up in one place."
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
        "status": "shipped",
        "case": "cs-forensics",
    },
    {
        "num": "05",
        "title": "Data Protection & Secrets Monitor",
        "skill": "Data Protection",
        "problem": "Secrets in environment variables, sensitive data in the wrong bucket, "
        "unencrypted storage, a committed access key.",
        "status": "shipped",
        "case": "cs-dataprotection",
    },
    {
        "num": "06",
        "title": "Secure Multi-Account Landing Zone",
        "skill": "Governance",
        "problem": "In one account, anyone with enough access can switch off the controls "
        "that watch them. Guardrails have to sit above the workloads.",
        "status": "shipped",
        "case": "cs-landingzone",
    },
    {
        "num": "07",
        "title": "Passwordless GitHub → AWS CI/CD",
        "skill": "IAM · DevSecOps",
        "problem": "Long-lived AWS keys in CI secrets never expire and get copied. OIDC "
        "replaces them with short-lived, scoped credentials.",
        "status": "shipped",
        "case": "cs-cicd",
    },
    {
        "num": "08",
        "title": "Security Operations Center Dashboard",
        "skill": "Detection · Security Operations",
        "problem": "Signals are scattered across GuardDuty, Security Hub, scanners and "
        "incidents. Nobody can answer: how exposed are we right now?",
        "status": "shipped",
        "case": "cs-soc",
    },
    {
        "num": "09",
        "title": "Terraform IaC Security Scanner",
        "skill": "Infrastructure Security · DevSecOps",
        "problem": "A public bucket in production is an incident. The same public bucket in a "
        "Terraform plan is a failed CI check — catch it before apply.",
        "status": "shipped",
        "case": "cs-terraform",
    },
    {
        "num": "10",
        "title": "Kubernetes Security",
        "skill": "Infrastructure Security · IAM",
        "problem": "A privileged container is root on the node; a cluster-admin binding is game "
        "over. These are YAML, approved in a pull request.",
        "status": "shipped",
        "case": "cs-k8s",
    },
    {
        "num": "11",
        "title": "Azure Posture Scanner",
        "skill": "Data Protection · Multi-cloud",
        "problem": "Security teams are rarely single-cloud. A posture tool that only speaks AWS "
        "is blind to half the estate.",
        "status": "shipped",
        "case": "cs-azure",
    },
    {
        "num": "12",
        "title": "Log Detection Pipeline (SIEM-lite)",
        "skill": "Detection · Incident Response",
        "problem": "Plenty of attacks are ordinary API calls that are only suspicious together. "
        "The signal is in the correlation over time, not any one record.",
        "status": "shipped",
        "case": "cs-siem",
    },
    {
        "num": "13",
        "title": "FinOps + Security-Cost Guardrails",
        "skill": "Governance · Incident Response",
        "problem": "When an account is cryptomined, the loudest early signal is the invoice — a "
        "compute spike hours before anyone reads the detection console.",
        "status": "shipped",
        "case": "cs-finops",
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
    {
        "id": "cs-forensics",
        "code": "CASE-04",
        "title": "Treating a Compromised Instance Like a Crime Scene",
        "domain": "Incident Response",
        "hook": "The reflex is to terminate a hacked instance. That destroys the evidence. This "
        "collects it in order of volatility, hashes every artifact, and writes an immutable "
        "chain of custody — and never terminates the box.",
        "metrics": [
            ("volatility order", "collection"),
            ("SHA-256", "every artifact"),
            ("WORM", "chain of custody"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "When an instance is compromised, the instinct is to kill it. But terminating "
                    "it throws away exactly what an investigation needs: the volatile memory and "
                    "process state, the disk, the network connections, the instance metadata. "
                    "Containment and evidence preservation pull in opposite directions unless the "
                    "response is designed for both.",
                ],
            },
            {
                "h": "Collection in order of volatility",
                "body": [
                    "Forensics runs when Project 1 isolates a host and publishes "
                    "<span class='mono'>Endon Forensics Requested</span> to the bus. The collector "
                    "gathers evidence most-volatile first — live process and network state over "
                    "SSM, then instance metadata, the console screenshot, recent CloudTrail "
                    "activity, and finally EBS snapshots of every attached volume — so the "
                    "fragile, disappearing signal is captured before the durable disk.",
                ],
            },
            {
                "h": "Integrity and chain of custody",
                "body": [
                    "Every artifact is hashed with SHA-256 as it is collected, and a manifest — "
                    "what was taken, when, from where, and its hash — is written to an S3 evidence "
                    "bucket with <strong>Object Lock</strong> in governance mode. The record is "
                    "write-once: it cannot be altered or deleted for the retention period, so the "
                    "evidence would stand up to scrutiny.",
                ],
            },
            {
                "h": "Preserve-only by construction",
                "points": [
                    "The forensics IAM role can snapshot and read, but an explicit deny blocks "
                    "<span class='mono'>Terminate</span>, <span class='mono'>Stop</span>, "
                    "<span class='mono'>Delete</span> and <span class='mono'>"
                    "BypassGovernanceRetention</span> — enforced by a test that fails the build if "
                    "a destructive permission is ever granted.",
                    "Collection is idempotent: a re-delivered request maps to the same case and "
                    "does not duplicate evidence.",
                    "Each collector is failure-isolated — if one source is unreachable it is "
                    "recorded as SKIPPED, and the rest still run.",
                ],
            },
            {
                "h": "Limitations & lessons",
                "body": [
                    "There is an honest tension: a fully isolated host may be unreachable over "
                    "SSM, so the most volatile capture can degrade to SKIPPED — the manifest says "
                    "so rather than pretending. The lesson was that chain-of-custody integrity "
                    "(hashes + WORM storage) matters more than collecting every last byte: "
                    "evidence you cannot trust is worse than evidence you are missing.",
                ],
            },
        ],
    },
    {
        "id": "cs-dataprotection",
        "code": "CASE-05",
        "title": "A Secret Scanner That Must Never Leak a Secret",
        "domain": "Data Protection",
        "hook": "A tool that hunts for exposed credentials is itself a tempting exfiltration "
        "path. This one masks every match to edge characters and a hash at the engine boundary, "
        "and its role can list secrets but never read their value.",
        "metrics": [
            ("signatures + entropy", "detection"),
            ("0", "plaintext emitted"),
            ("List, not Get", "Secrets Manager"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "Credentials leak into places that are easy to forget: a Lambda environment "
                    "variable, EC2 user data, an object in the wrong bucket. A monitor that finds "
                    "them has to handle the very thing it is looking for — so if it ever logs, "
                    "stores, or emits a matched secret, it has become the leak.",
                ],
            },
            {
                "h": "The detection engine",
                "body": [
                    "Detection combines signatures for known formats (AWS keys, GitHub tokens, "
                    "Stripe keys, private keys, database connection strings) with a Shannon-"
                    "entropy check that catches high-entropy strings no signature knows. A "
                    "placeholder suppressor keeps obvious dummies like "
                    "<span class='mono'>changeme</span> or <span class='mono'>example</span> from "
                    "firing, so the findings are worth reading.",
                ],
            },
            {
                "h": "Never handle the plaintext",
                "body": [
                    "The core rule is that a secret's value never leaves the engine. At the "
                    "boundary, <span class='mono'>redact()</span> reduces every match to a few "
                    "edge characters plus a SHA-256 digest — enough to correlate and confirm, "
                    "never enough to use. A test asserts the monitor never emits or logs a "
                    "secret's plaintext.",
                ],
            },
            {
                "h": "Least privilege enforced by the build",
                "points": [
                    "The scanning role holds <span class='mono'>secretsmanager:ListSecrets</span> "
                    "but <em>not</em> <span class='mono'>GetSecretValue</span> — it can see that a "
                    "secret exists, never read it — enforced by a synthesis test.",
                    "Inspection permissions across Lambda, EC2 and Macie are read-only; the "
                    "monitor cannot change a resource.",
                ],
            },
            {
                "h": "One system",
                "body": [
                    "Amazon Macie findings for publicly reachable sensitive data are normalized to "
                    "<span class='mono'>DataProtection:S3/SensitiveDataPubliclyAccessible</span> "
                    "and handed to the Project 1 response engine, which re-closes the bucket. AWS "
                    "Health exposed-credential events become findings the same way. Detection and "
                    "response are two components, one platform.",
                ],
            },
        ],
    },
    {
        "id": "cs-landingzone",
        "code": "CASE-06",
        "title": "The Controls an Administrator Can't Turn Off",
        "domain": "Security Foundations & Governance",
        "hook": "Inside one account, whoever has enough access can switch off the controls that "
        "watch them. Service Control Policies sit above the accounts — and an SCP simulator "
        "proves a full admin is denied 10 of 10 dangerous actions.",
        "metrics": [
            ("10/10", "admin actions blocked"),
            ("7", "SCP guardrails"),
            ("above the account", "enforced"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "In a single account, IAM is both the floor and the ceiling: an administrator "
                    "can grant themselves anything and disable anything — stop CloudTrail, turn "
                    "off GuardDuty, make a bucket public. Security that the monitored party can "
                    "switch off is theatre.",
                ],
            },
            {
                "h": "SCPs as the control plane",
                "body": [
                    "The non-negotiable rules live in Service Control Policies attached to "
                    "Organizational Units above the workload accounts. An explicit "
                    "<span class='mono'>Deny</span> in an SCP cannot be overridden by any IAM "
                    "policy in the member account — not by an administrator, not by the root user. "
                    "The guardrails are deny-based over the default allow-all, which is simpler "
                    "and safer than allow-lists.",
                ],
            },
            {
                "h": "The guardrail proof",
                "body": [
                    "A landing-zone diagram is easy to get subtly wrong, so the project ships a "
                    "small SCP evaluation engine and runs the attacker's playbook against the "
                    "guardrails that apply to the Production account:",
                ],
                "pre": "GUARDRAIL PROOF — a full admin in the Production account\n"
                "  [DENIED ] Stop CloudTrail logging            <- ProtectSecurityLogging\n"
                "  [DENIED ] Disable GuardDuty                  <- ProtectDetectionServices\n"
                "  [DENIED ] Remove account Block Public Access <- PreventPublicS3\n"
                "  [DENIED ] Operate in an unapproved region    <- RegionAllowlist\n"
                "  [DENIED ] Modify the Endon response engine   <- ProtectPlatform\n"
                "  [DENIED ] Leave the organization             <- PreventLeavingOrg\n\n"
                "  10/10 dangerous actions blocked by SCP for a workload administrator.",
            },
            {
                "h": "Break-glass without holes",
                "body": [
                    "An over-eager guardrail that blocks the security team gets switched off in "
                    "week one, so the high-impact guardrails exempt exactly the security admin "
                    "(and, for the platform's own resources, the deploy pipeline) via "
                    "<span class='mono'>aws:PrincipalArn</span>. The simulator proves both sides: "
                    "the attacker is stopped, the break-glass path still works.",
                ],
            },
            {
                "h": "The platform comes full circle",
                "body": [
                    "Project 1 had one residual risk it couldn't close alone: an account admin "
                    "disabling the responder. The <span class='mono'>protect-endon-platform</span> "
                    "SCP closes it — the responder can only be changed by the deploy pipeline. The "
                    "landing zone is what makes the automated responder trustworthy in a real org.",
                ],
            },
        ],
    },
    {
        "id": "cs-cicd",
        "code": "CASE-07",
        "title": "A Deploy Key That Can't Leak and Can't Escalate",
        "domain": "IAM · Governance",
        "hook": "No AWS keys in GitHub. OIDC federation scopes trust to one repository and "
        "branch, and a permissions boundary contains a compromised pipeline — both proven by "
        "red-teaming the trust and the blast radius offline.",
        "metrics": [
            ("0", "long-lived keys"),
            ("5/5", "rogue assumes denied"),
            ("6/6", "escalations denied"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "The usual CI pattern — a long-lived access key in repository secrets — fails "
                    "two ways: the key never expires and gets copied into more places than anyone "
                    "tracks, and the deploy identity is over-powered, so whoever controls the "
                    "pipeline controls the account.",
                ],
            },
            {
                "h": "Keyless trust",
                "body": [
                    "There are no AWS keys in GitHub. The account trusts GitHub's OIDC provider "
                    "through <span class='mono'>sts:AssumeRoleWithWebIdentity</span>, pinned by "
                    "two conditions on the token: the audience is AWS STS, and the "
                    "<span class='mono'>sub</span> is <span class='mono'>repo:owner/repo:ref:refs/"
                    "heads/main</span>. A fork, a pull request, a feature branch, a tag, or any "
                    "other repository produces a different subject and is refused by STS. Tokens "
                    "last minutes, not forever.",
                ],
            },
            {
                "h": "A hard ceiling on the blast radius",
                "body": [
                    "The deploy role's identity policy grants only <span class='mono'>"
                    "sts:AssumeRole</span> on the CDK roles. On top, a customer-managed "
                    "permissions boundary <em>denies</em> the escalation and destruction set — "
                    "creating users, minting keys, attaching policies, passing roles, deleting "
                    "buckets. Because an explicit deny wins, the ceiling holds even if the "
                    "identity policy is later widened to administrator, which is exactly the "
                    "compromised-pipeline case.",
                ],
                "pre": "BLAST RADIUS OF A COMPROMISED PIPELINE\n"
                "  [ALLOWED] Assume the CDK deploy role\n"
                "  [DENIED ] Create an IAM user (persistence)\n"
                "  [DENIED ] Attach AdministratorAccess to itself\n"
                "  [DENIED ] Pass a privileged role\n"
                "  [DENIED ] Delete an S3 bucket (destroy data)\n\n"
                "  5/5 unauthorized assume attempts denied.\n"
                "  6/6 dangerous pipeline actions denied.",
            },
            {
                "h": "Gate on your own evidence",
                "body": [
                    "The pipeline is keyless and bounded — and it refuses to ship an insecure "
                    "change. Before it deploys it runs Project 2's IAM analyzer (fail on any "
                    "CRITICAL) and after it deploys, Project 3's posture scanner (fail on any "
                    "HIGH). The pipeline that ships the platform is guarded by the platform.",
                ],
            },
        ],
    },
    {
        "id": "cs-soc",
        "code": "CASE-08",
        "title": "One Number You Can Actually Trust",
        "domain": "Detection · Security Operations",
        "hook": "One read-only view over the whole platform, with a security score where every "
        "deducted point traces to a finding — and a green board can't hide a switched-off "
        "detector.",
        "metrics": [
            ("read-only", "by construction"),
            ("explainable", "security score"),
            ("Cognito + MFA", "every route"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "Eight security tools produce plenty of signal and no single answer to the "
                    "question a lead actually asks: how exposed are we right now? And a dashboard "
                    "that aggregates every weakness is itself a liability — if it can act, it is a "
                    "foothold; if it serves unauthenticated, it hands out the map.",
                ],
            },
            {
                "h": "An explainable score",
                "body": [
                    "The headline number is a pure function with published weights: start at 100, "
                    "subtract a super-linear weight per open finding (one CRITICAL outranks twenty "
                    "LOWs), and subtract a penalty for every detective control that is switched "
                    "off. The board shows the arithmetic, so a security lead can disagree with a "
                    "weight rather than distrust the whole number.",
                ],
                "pre": "ENDON AI — SECURITY OPERATIONS CENTER\n"
                "  Security Score   28/100   (grade F)\n"
                "  -60 findings, -12 blind spots\n"
                "  Critical 1   High 2   Medium 2   Low 1\n"
                "  GuardDuty ACTIVE   Security Hub INACTIVE   CloudTrail ACTIVE   Config ACTIVE",
            },
            {
                "h": "Blind spots count against you",
                "body": [
                    "A findings-only score looks greenest exactly when a detector is off, because "
                    "a disabled detector produces no findings. So the SOC probes GuardDuty, "
                    "Security Hub, CloudTrail and Config, and a detector whose state it cannot "
                    "confirm is treated as a blind spot — never as coverage.",
                ],
            },
            {
                "h": "Read-only and authenticated by construction",
                "points": [
                    "No route mutates state, and the deploy role has read-only access to the "
                    "tables (get/query/scan, never put or delete) — enforced by a synthesis test. "
                    "A dashboard that cannot write cannot be turned into a weapon.",
                    "Every API Gateway route sits behind Amazon Cognito with MFA required; the "
                    "map of the platform's weaknesses is never served unauthenticated.",
                    "The FastAPI app runs on Lambda through a dependency-free ASGI adapter, "
                    "keeping the bundle to Endon's own packages plus the runtime's boto3.",
                ],
            },
        ],
    },
    {
        "id": "cs-terraform",
        "code": "CASE-09",
        "title": "Catching the Public Bucket in the Pull Request",
        "domain": "Infrastructure Security · DevSecOps",
        "hook": "A public bucket in production is an incident. The same public bucket in a "
        "Terraform plan is a failed CI check. This scans the plan — what Terraform will actually "
        "create — and blocks the apply.",
        "metrics": [
            ("13", "IaC controls"),
            ("plan, not HCL", "resolved values"),
            ("0", "false positives"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "Project 3 finds a public bucket in a <em>running</em> account — after it "
                    "exists, after it may already have leaked. The cheaper place to catch it is "
                    "the pull request that introduced it, where the Terraform that will create the "
                    "bucket is right there, reviewable, before anything is provisioned.",
                ],
            },
            {
                "h": "Scan the plan, not the HCL",
                "body": [
                    "The scanner reads the JSON that <span class='mono'>terraform show -json</span> "
                    "emits, not raw <span class='mono'>.tf</span>. That's the right layer: "
                    "variables, defaults and modules are already resolved, so a rule sees the "
                    "<em>real</em> value of an attribute — not <span class='mono'>var.acl</span> — "
                    "and it's plain JSON, so the tests need no Terraform binary.",
                ],
            },
            {
                "h": "Reusing the platform's brain",
                "body": [
                    "The IAM rules lift the policy JSON out of the plan and run it through "
                    "<em>Project 2's</em> evaluator — the same deny-wins engine that grades live "
                    "accounts. An <span class='mono'>Action:* Resource:*</span> policy is "
                    "administrator-equivalent whether it's live or still a string in a plan, judged "
                    "by one piece of code in both places.",
                ],
            },
            {
                "h": "Prove it, and gate on it",
                "body": [
                    "A deliberately insecure stack trips all 13 controls; its hardened twin trips "
                    "none — a measured benchmark, not a claim. The CLI exits non-zero on any "
                    "blocking finding, so it drops into the Project 7 pipeline as the pre-apply "
                    "gate, next to the IAM and posture gates.",
                ],
                "pre": "ENDON AI - TERRAFORM IaC SECURITY SCAN\n"
                ">> [CRITICAL] TF-IAM-001  aws_iam_policy.admin   admin-equivalent policy\n"
                ">> [CRITICAL] TF-S3-001   aws_s3_bucket.public   bucket exposed publicly\n"
                "   ... 13 more ...\n"
                "  Gate (fail-on HIGH): FAILED - 11 blocking",
            },
            {
                "h": "And it writes Terraform, not just reads it",
                "body": [
                    "The project re-provisions the Endon platform baseline (KMS, DynamoDB tables, "
                    "Object Lock evidence bucket) as an idiomatic Terraform module — written to "
                    "pass its own scanner. The guardrail and the infrastructure it guards agree.",
                ],
            },
        ],
    },
    {
        "id": "cs-k8s",
        "code": "CASE-10",
        "title": "Rejecting the Privileged Pod at the Door",
        "domain": "Infrastructure Security · IAM",
        "hook": "A privileged container is root on the node; a cluster-admin binding is game over. "
        "This scans workloads and RBAC, and — like a real admission webhook — refuses the "
        "dangerous pod before it is ever created.",
        "metrics": [
            ("17", "controls (pod + RBAC)"),
            ("admission", "simulator + Kyverno"),
            ("0", "false positives"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "The dangerous Kubernetes misconfigurations are configuration, not exploits — a "
                    "debug pod left <span class='mono'>privileged</span>, a ServiceAccount with "
                    "<span class='mono'>get secrets</span> cluster-wide. Both are YAML, both get "
                    "reviewed, both get approved.",
                ],
            },
            {
                "h": "Two tools: workloads and RBAC",
                "body": [
                    "A pod-security scanner flags privileged containers, host namespaces, "
                    "<span class='mono'>hostPath</span>, missing limits, dangerous capabilities and "
                    "mutable images. And RBAC — the cluster's IAM — gets the same treatment as "
                    "<em>Project 2</em>: wildcard roles, cluster-wide Secret reads, "
                    "<span class='mono'>bind</span>/<span class='mono'>escalate</span>, and any "
                    "binding to <span class='mono'>cluster-admin</span>.",
                ],
            },
            {
                "h": "Enforce at admission, prove it offline",
                "body": [
                    "In a cluster, a validating webhook (Kyverno) rejects a bad pod at creation. "
                    "This is that decision in Python — deny any pod with a blocking finding, "
                    "sharing the scanner's rules — so the exact policy can be <strong>unit-tested "
                    "before it reaches a cluster</strong>. The real Kyverno ClusterPolicies deploy "
                    "the same intent.",
                ],
                "pre": "ADMISSION CONTROL (what a validating webhook would do)\n"
                "  denied  Deployment/legacy-api: privileged; host namespace; hostPath; runs as root ...\n"
                "  admitted Deployment/hardened-api",
            },
            {
                "h": "Proving coverage",
                "body": [
                    "A deliberately insecure workload trips all 11 pod controls; insecure RBAC "
                    "trips all 6; the hardened counterparts trip none. And because a Kubernetes "
                    "finding is the same <span class='mono'>endon_core.Finding</span> as an AWS "
                    "one, it lands in the same SOC — so \"how exposed are we?\" spans the cluster "
                    "and the cloud.",
                ],
            },
        ],
    },
    {
        "id": "cs-azure",
        "code": "CASE-11",
        "title": "The Same Risk, in the Other Cloud",
        "domain": "Data Protection · Multi-cloud",
        "hook": "The dangerous states translate across clouds: a public S3 bucket is a Storage "
        "account with public blob access. This covers Azure's core CSPM checks in the same "
        "finding format as AWS.",
        "metrics": [
            ("9", "Azure CSPM controls"),
            ("1 query", "Resource Graph inventory"),
            ("2 clouds", "one SOC"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "Security teams are rarely single-cloud. A company runs its product on AWS and "
                    "its analytics on Azure, and a posture tool that only speaks AWS is blind to "
                    "half the estate — green dashboard, exposed data.",
                ],
            },
            {
                "h": "The insight: the risks translate",
                "body": [
                    "Azure's misconfigurations aren't new risks; they're the same risks with "
                    "different property names. A public bucket is <span class='mono'>"
                    "allowBlobPublicAccess = true</span>; a <span class='mono'>0.0.0.0/0</span> "
                    "security group is an NSG rule sourced from <span class='mono'>Internet</span>; "
                    "an unencrypted disk is a managed disk with no encryption. Supporting Azure is "
                    "mapping each cloud's spelling of a hazard to the same control and finding.",
                ],
            },
            {
                "h": "One finding format does the heavy lifting",
                "body": [
                    "The Azure scanner produces <span class='mono'>AzurePosture:Storage/"
                    "BlobPublicAccess</span> the way the AWS scanner produces "
                    "<span class='mono'>Posture:S3/BucketPubliclyAccessible</span>, tags it "
                    "<span class='mono'>cloud=azure</span>, and it flows into the same SOC and ASFF "
                    "feed — without a line of SOC-side change.",
                ],
            },
            {
                "h": "Reading Azure like a real CSPM tool",
                "body": [
                    "The scanner runs on <strong>Azure Resource Graph</strong> — one KQL query "
                    "that returns every resource's properties, the way production CSPM inventories "
                    "a subscription. The live Azure SDK is an optional extra; the checks run "
                    "offline on JSON. An insecure subscription trips all 9 controls; a hardened one "
                    "trips none.",
                ],
            },
        ],
    },
    {
        "id": "cs-siem",
        "code": "CASE-12",
        "title": "The Attack Made of Ordinary API Calls",
        "domain": "Detection · Incident Response",
        "hook": "Plenty of attacks are ordinary API calls that are only suspicious together. This "
        "SIEM engine correlates CloudTrail over time — a burst of GetObject, repeated failed "
        "logins — and maps every detection to MITRE ATT&CK.",
        "metrics": [
            ("11", "detections"),
            ("windowed", "correlation per principal"),
            ("Sigma", "portable to any SIEM"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "GuardDuty is great at what it flags, but many attacks are made of ordinary "
                    "calls that are only suspicious <em>together</em>. One "
                    "<span class='mono'>GetObject</span> is a download; two hundred in five minutes "
                    "is exfiltration. The signal is in the correlation across a principal's "
                    "activity over time — that's continuous monitoring.",
                ],
            },
            {
                "h": "Two kinds of rule, because attacks have two shapes",
                "body": [
                    "Single-event rules match one record — root usage, "
                    "<span class='mono'>StopLogging</span>, admin attached, a bucket made public. "
                    "Correlation rules slide a time window over one principal's activity: a burst "
                    "of GetObject (exfiltration), repeated failed logins (brute force), a scan of "
                    "Describe/List calls (reconnaissance), the same credentials from two IPs.",
                ],
            },
            {
                "h": "Every finding names the adversary's move",
                "body": [
                    "Each detection carries a MITRE ATT&CK technique — T1530 for the mass "
                    "download, T1110 for the brute force — so the output isn't \"something fired,\" "
                    "it's \"this principal is exfiltrating data,\" which is what an analyst or an "
                    "automated responder prioritises on.",
                ],
                "pre": ">> 10:05:40 [HIGH]     SIEM-101  mallory  (T1530)  Mass S3 download (exfiltration)\n"
                ">> 10:06:45 [HIGH]     SIEM-102  admin    (T1110)  Console login brute force\n"
                "  11 detections on the attack log   -   0 on a benign day",
            },
            {
                "h": "Portable by design",
                "body": [
                    "The single-event detections also ship as <strong>Sigma</strong> — the "
                    "vendor-neutral rule format that converts to Splunk and Elastic. The engine "
                    "proves the logic offline in the platform's finding format; Sigma carries the "
                    "same logic into whatever SIEM the company already runs.",
                ],
            },
        ],
    },
    {
        "id": "cs-finops",
        "code": "CASE-13",
        "title": "The Compromise That Showed Up on the Invoice First",
        "domain": "Governance · Incident Response",
        "hook": "When an account is cryptomined, the first signal is often the invoice — compute "
        "spikes 16x overnight. This treats the bill as a detector, and flags ordinary waste in "
        "the same pass.",
        "metrics": [
            ("16x", "compute spike caught"),
            ("cost = detector", "FinOps + security"),
            ("read-only", "no extra tooling"),
        ],
        "sections": [
            {
                "h": "The problem",
                "body": [
                    "When an attacker mines cryptocurrency in a compromised account, the loudest "
                    "early signal isn't a GuardDuty finding — it's the bill. Compute cost jumps "
                    "16x overnight in a region nobody uses; exfiltration spikes data-transfer-out. "
                    "Finance sees a scary number and files a ticket about \"unexpected AWS spend,\" "
                    "and nobody connects it to security for days.",
                ],
            },
            {
                "h": "The bill is a detector",
                "body": [
                    "The analyzer builds daily cost series and flags spikes — compute "
                    "(cryptomining), data-transfer-out (exfiltration), spend in a region never used "
                    "before — and in the same pass flags waste: untagged spend, money paid for "
                    "idle Elastic IPs. FinOps and security fall out of the same data.",
                ],
            },
            {
                "h": "Explainable over clever",
                "body": [
                    "Nobody actions a black-box \"anomaly score\" on an invoice. Every finding "
                    "shows its arithmetic — <span class='mono'>compute $683.60 (16x baseline)</span>, "
                    "<span class='mono'>$380 first appeared in ap-south-1</span> — and dollar floors "
                    "keep cheap variance from ever crying wolf.",
                ],
            },
            {
                "h": "It corroborates the whole platform",
                "body": [
                    "A compute-spike finding is now an <span class='mono'>endon_core.Finding</span>, "
                    "so it lands in the same SOC as the GuardDuty cryptomining finding (Project 1) "
                    "and the CloudTrail detections (Project 12) for the same incident. Three "
                    "independent signals — a detector, a log correlation and the bill — pointing at "
                    "the same instance, on one screen.",
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
        "I'm preparing for the AWS Certified Security – Specialty certification, and Endon AI is "
        "how I turned that study into evidence: all eight components are built, tested and "
        "deployable, mapped to the exam's six domains.",
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
