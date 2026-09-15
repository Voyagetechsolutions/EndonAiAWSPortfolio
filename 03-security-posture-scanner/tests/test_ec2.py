import pytest

from endon_posture.checks.base import (
    permission_is_all_protocols,
    permission_is_open_to_internet,
    permission_matches_port,
)
from endon_posture.checks.ec2 import security_groups


def _tcp(from_port, to_port, cidr="0.0.0.0/0"):
    return {
        "IpProtocol": "tcp",
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": [{"CidrIp": cidr}],
    }


@pytest.mark.parametrize(
    ("permission", "port", "expected"),
    [
        (_tcp(22, 22), 22, True),
        (_tcp(0, 1024), 22, True),
        (_tcp(80, 80), 22, False),
        ({"IpProtocol": "-1", "IpRanges": []}, 22, True),  # all protocols cover every port
        (_tcp(3389, 3389), 3389, True),
        ({"IpProtocol": "udp", "FromPort": 22, "ToPort": 22}, 22, False),
    ],
)
def test_permission_matches_port(permission, port, expected):
    assert permission_matches_port(permission, port) is expected


def test_open_to_internet_detects_v4_and_v6():
    assert permission_is_open_to_internet({"IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    assert permission_is_open_to_internet({"Ipv6Ranges": [{"CidrIpv6": "::/0"}]})
    assert not permission_is_open_to_internet({"IpRanges": [{"CidrIp": "10.0.0.0/8"}]})


def controls_for(ctx, group_id):
    return {
        f.control_id for f in security_groups(ctx) if any(group_id in r.id for r in f.resources)
    }


def _group(aws, name, permissions):
    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    if permissions:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=permissions)
    return gid


def test_ssh_and_rdp_open_are_flagged(ctx, aws):
    gid = _group(ctx.clients, "web", [_tcp(22, 22), _tcp(3389, 3389)])
    controls = controls_for(ctx, gid)
    assert "EC2-001" in controls
    assert "EC2-002" in controls
    assert "EC2-003" not in controls


def test_all_protocols_open_is_flagged_as_all_ports(ctx, aws):
    gid = _group(ctx.clients, "open", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    controls = controls_for(ctx, gid)
    assert "EC2-003" in controls
    # When everything is open, do not also raise the more specific SSH/RDP controls.
    assert "EC2-001" not in controls
    assert "EC2-002" not in controls


def test_scoped_ingress_is_not_flagged(ctx, aws):
    gid = _group(ctx.clients, "locked", [_tcp(22, 22, cidr="10.0.0.0/8")])
    assert controls_for(ctx, gid) == set()


def test_all_protocols_helper():
    assert permission_is_all_protocols({"IpProtocol": "-1"})
    assert not permission_is_all_protocols({"IpProtocol": "tcp"})
