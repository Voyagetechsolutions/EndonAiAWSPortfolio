"""The organization structure: organizational units, accounts and SCP attachments.

The structure follows AWS multi-account best practice: a dedicated Security OU (with a
Security Tooling account that runs Endon AI and a Log Archive account that owns the
immutable audit logs), a Workloads OU split into Production and Development, and a Sandbox
OU. SCPs attach to OUs; an account inherits every SCP along its path to the root.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from endon_landingzone.scps import SCP_CATALOG, Scp


@dataclass
class Account:
    name: str
    purpose: str
    email: str = ""


@dataclass
class OrgUnit:
    name: str
    children: list[OrgUnit] = field(default_factory=list)
    accounts: list[Account] = field(default_factory=list)

    def walk(self) -> list[OrgUnit]:
        units = [self]
        for child in self.children:
            units.extend(child.walk())
        return units

    def find(self, name: str) -> OrgUnit | None:
        for unit in self.walk():
            if unit.name == name:
                return unit
        return None

    def all_accounts(self) -> list[Account]:
        accounts = list(self.accounts)
        for child in self.children:
            accounts.extend(child.all_accounts())
        return accounts


@dataclass
class Organization:
    root: OrgUnit
    catalog: tuple[Scp, ...] = SCP_CATALOG

    def scps_for_ou(self, name: str) -> list[Scp]:
        """SCPs directly attached to one OU."""
        return [scp for scp in self.catalog if name in scp.targets]

    def path_to(self, ou_name: str) -> list[OrgUnit]:
        """The OUs from the root down to (and including) the named OU."""
        path = _find_path(self.root, ou_name)
        if path is None:
            raise KeyError(ou_name)
        return path

    def effective_scps(self, ou_name: str) -> list[Scp]:
        """Every SCP that applies to an account in the named OU (path union, de-duplicated)."""
        seen: dict[str, Scp] = {}
        for unit in self.path_to(ou_name):
            for scp in self.scps_for_ou(unit.name):
                seen.setdefault(scp.id, scp)
        return list(seen.values())


def _find_path(unit: OrgUnit, target: str) -> list[OrgUnit] | None:
    if unit.name == target:
        return [unit]
    for child in unit.children:
        sub = _find_path(child, target)
        if sub is not None:
            return [unit, *sub]
    return None


def build_endon_organization() -> Organization:
    root = OrgUnit(
        name="Root",
        children=[
            OrgUnit(
                name="Security",
                accounts=[
                    Account("SecurityTooling", "Delegated admin; runs the Endon AI platform"),
                ],
                children=[
                    OrgUnit(
                        name="LogArchive",
                        accounts=[
                            Account(
                                "LogArchive", "Immutable organization CloudTrail and Config history"
                            )
                        ],
                    )
                ],
            ),
            OrgUnit(
                name="Workloads",
                children=[
                    OrgUnit("Production", accounts=[Account("Production", "Production workloads")]),
                    OrgUnit(
                        "Development", accounts=[Account("Development", "Development workloads")]
                    ),
                ],
            ),
            OrgUnit(
                "Sandbox", accounts=[Account("Sandbox", "Experimentation, tightly guardrailed")]
            ),
        ],
    )
    return Organization(root=root)
