import sys

from app.services.remediation import execute_remediation
from app.services.scans import execute_scan


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"scan", "remediate"}:
        print("Usage: python -m app.worker (scan|remediate) ID", file=sys.stderr)
        return 2
    object_id = int(sys.argv[2])
    if sys.argv[1] == "scan":
        execute_scan(object_id)
    else:
        execute_remediation(object_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

