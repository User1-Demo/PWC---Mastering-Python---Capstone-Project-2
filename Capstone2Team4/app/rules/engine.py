from datetime import datetime, timezone
from typing import Any

SUPPORTED_RULES = {
    "required_tags",
    "nsg_open_ports",
    "idle_vm",
    "unattached_disk",
    "expiring_secret",
}
SEVERITIES = {"low", "medium", "high", "critical"}
AUTO_REMEDIABLE_RULES = {"required_tags"}


def validate_rule(rule_type: str, severity: str, parameters: dict[str, Any], auto_remediate: bool) -> None:
    if rule_type not in SUPPORTED_RULES:
        raise ValueError(f"Unsupported rule_type: {rule_type}")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")
    if auto_remediate and (rule_type not in AUTO_REMEDIABLE_RULES or severity != "low"):
        raise ValueError("Only low-severity required_tags rules may be auto-remediated")
    if rule_type == "required_tags":
        required = parameters.get("required_tags")
        if not isinstance(required, list) or not required or not all(
            isinstance(tag, str) and tag.strip() for tag in required
        ):
            raise ValueError("required_tags requires a non-empty list of tag names")
        if auto_remediate:
            values = parameters.get("tag_values")
            if not isinstance(values, dict) or any(
                tag not in values or not isinstance(values[tag], str) or not values[tag].strip()
                for tag in required
            ):
                raise ValueError("auto-remediation requires an explicit non-empty tag_values entry for each required tag")
    if rule_type == "nsg_open_ports":
        blocked = parameters.get("blocked_ports", [22, 3389])
        if not isinstance(blocked, list) or not all(
            isinstance(port, int) and 1 <= port <= 65535 for port in blocked
        ):
            raise ValueError("blocked_ports must be a list of TCP/UDP port numbers")
        remediation_action = parameters.get("remediation_action")
        if remediation_action not in {None, "deny_exposed_rules"}:
            raise ValueError("nsg_open_ports remediation_action must be 'deny_exposed_rules'")
        if remediation_action and severity not in {"high", "critical"}:
            raise ValueError("NSG rule remediation requires high or critical severity")
    if rule_type == "idle_vm" and not 0 <= float(parameters.get("cpu_threshold_percent", 5)) <= 100:
        raise ValueError("cpu_threshold_percent must be between 0 and 100")
    if rule_type == "expiring_secret" and int(parameters.get("days", 30)) < 1:
        raise ValueError("days must be at least 1")


def evaluate_resource(resource: dict, rules: list) -> list[dict]:
    findings = []
    resource_type = (resource.get("type") or "").lower()
    props = resource.get("properties") or {}
    tags = resource.get("tags") or {}
    for rule in rules:
        if not rule.enabled:
            continue
        params = rule.parameters or {}
        details: dict | None = None
        if rule.rule_type == "required_tags":
            missing = [tag for tag in params["required_tags"] if not tags.get(tag)]
            if missing:
                details = {"missing_tags": missing, "required_tags": params["required_tags"]}
        elif rule.rule_type == "nsg_open_ports" and "microsoft.network/networksecuritygroups" in resource_type:
            blocked = set(params.get("blocked_ports", [22, 3389]))
            exposed = []
            for security_rule in props.get("securityRules", []):
                sources = security_rule.get("sourceAddressPrefixes") or [
                    security_rule.get("sourceAddressPrefix", "")
                ]
                ports = security_rule.get("destinationPortRanges") or [
                    security_rule.get("destinationPortRange", "")
                ]
                for source in sources:
                    for port in ports:
                        port_str = str(port)
                        if (
                            security_rule.get("direction", "").lower() == "inbound"
                            and security_rule.get("access", "").lower() == "allow"
                            and str(source).lower() in {"*", "internet", "0.0.0.0/0", "::/0"}
                            and (port_str == "*" or bool(_port_parts(port_str) & blocked))
                        ):
                            exposed.append({"rule": security_rule.get("name"), "port": port_str})
            if exposed:
                details = {"exposed_rules": exposed}
        elif rule.rule_type == "idle_vm" and "microsoft.compute/virtualmachines" in resource_type:
            cpu = props.get("average_cpu_percent")
            threshold = float(params.get("cpu_threshold_percent", 5))
            if cpu is not None and float(cpu) <= threshold:
                details = {"average_cpu_percent": float(cpu), "threshold_percent": threshold}
        elif rule.rule_type == "unattached_disk" and "microsoft.compute/disks" in resource_type:
            if str(props.get("diskState", "")).lower() == "unattached":
                details = {"disk_state": props.get("diskState")}
        elif rule.rule_type == "expiring_secret" and "microsoft.keyvault/vaults/secrets" in resource_type:
            expiry = props.get("expires_on")
            if expiry:
                expires = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                remaining_days = (expires - datetime.now(timezone.utc)).total_seconds() / 86400
                if remaining_days <= int(params.get("days", 30)):
                    details = {"expires_on": expires.isoformat(), "days_remaining": round(remaining_days, 2)}
        if details is not None:
            findings.append(
                {
                    "rule": rule,
                    "resource": resource,
                    "title": f"{rule.name}: {resource.get('name') or resource.get('id')}",
                    "details": details,
                }
            )
    return findings


def _port_parts(value: str) -> set[int]:
    ports: set[int] = set()
    for part in value.split(","):
        try:
            if "-" in part:
                start, end = (int(piece) for piece in part.split("-", 1))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        except ValueError:
            continue
    return ports
