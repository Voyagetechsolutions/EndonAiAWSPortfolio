"""Endon AI automated threat detection and response.

GuardDuty, Security Hub and Endon findings arrive through EventBridge, are
normalized into a common ``Finding``, matched to a playbook, and contained by
guarded response actions. Every step is recorded on an incident timeline.
"""
