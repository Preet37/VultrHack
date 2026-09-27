import ipaddress
import json

from instance_lifecycle import validated_vpc_subnet


def validated_nic_report(body, vpc_subnet):
    if not isinstance(body, bytes) or len(body) > 256:
        raise ValueError("NIC report exceeds the allowed size")
    subnet = validated_vpc_subnet(vpc_subnet)
    try:
        report = json.loads(body)
    except (ValueError, UnicodeError):
        raise ValueError("NIC report must be JSON") from None
    if not isinstance(report, dict) or set(report) != {"probe", "vpc_ip"} or report["probe"] not in ("ok", "unavailable"):
        raise ValueError("NIC report must contain only bounded status fields")
    address = report["vpc_ip"]
    if address is not None:
        if not isinstance(address, str):
            raise ValueError("NIC address must be a private IPv4 string")
        try:
            address = ipaddress.IPv4Address(address)
        except (TypeError, ValueError):
            raise ValueError("NIC address must be a private IPv4 string") from None
        if address not in subnet or address in (subnet.network_address, subnet.broadcast_address) or report["probe"] != "ok":
            raise ValueError("NIC address is outside the approved VPC")
        report["vpc_ip"] = str(address)
    return report
