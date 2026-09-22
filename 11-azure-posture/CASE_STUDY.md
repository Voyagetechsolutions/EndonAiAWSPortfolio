# Case Study: The Same Risk, in the Other Cloud

## Context

A company runs its product on AWS and its analytics on Azure. The AWS side has a posture scanner
(Project 3) watching for public buckets and open security groups. The Azure side has nothing —
so when someone flips a Storage account to allow public blob access to "quickly share a report",
and leaves an NSG rule open to the Internet from a migration, no one sees it. The security team's
dashboard is green, because the dashboard only knows about AWS. Half the estate is a blind spot.

## The insight: the dangerous states translate

Azure's misconfigurations aren't new risks; they're the same risks with different property
names. A public S3 bucket is a Storage account with `allowBlobPublicAccess = true`. A
`0.0.0.0/0` security group is an NSG rule whose `sourceAddressPrefix` is `Internet`. An
unencrypted EBS volume is a managed disk with no `encryption`. So "supporting Azure" isn't
inventing a new scanner — it's mapping each cloud's spelling of a hazard to the same control
idea, and emitting the same finding.

## One finding format does the heavy lifting

Because every Endon component speaks `endon_core.Finding`, the Azure scanner didn't need its own
report format, its own storage, or its own SOC panel. It produces `AzurePosture:Storage/BlobPublicAccess`
the way the AWS scanner produces `Posture:S3/BucketPubliclyAccessible`, tags it `cloud=azure`,
and it flows into the same bus, the same incident store, the same Security Hub ASFF feed. The SOC
(Project 8) now answers "how exposed are we right now?" across both clouds without a line of
SOC-side change.

## Reading Azure the way a real CSPM tool does

The scanner runs on **Azure Resource Graph** output — one KQL query that returns every resource's
`properties`. That's how production CSPM tools inventory a subscription: not an API call per
service, but a single graph query. And because the checks operate on that JSON, the whole thing
is testable offline against committed fixtures, with the live Azure SDK kept as an optional extra
— the same offline-first discipline the moto-backed AWS projects use.

## Proving it

An insecure subscription trips all nine controls; a hardened one trips none:

```text
9 findings on the insecure subscription   (CRITICAL 1  HIGH 4  MEDIUM 4)
0 findings on the hardened subscription
Gate (fail-on HIGH): FAILED -> PASSED
```

## Takeaways

- Multi-cloud security is mostly translation: map each cloud's property names to one control idea
  and one finding, and the platform absorbs the second cloud.
- Inventorying via Resource Graph (one query) is both simpler to build and closer to how real
  tools work than walking each management API.
- The investment in a shared finding format keeps paying off — a whole second cloud cost a
  catalog and a handful of predicates.
