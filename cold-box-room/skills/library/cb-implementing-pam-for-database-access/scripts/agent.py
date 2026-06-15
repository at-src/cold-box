#!/usr/bin/env python3
# cold-box — copied from ACS scripts/agent.py (run via run_skill_script)
"""PAM Database Access Agent - audits privileged database sessions and access controls."""

import json
import argparse
import logging
import subprocess
import os
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def query_db_users(db_type, host, admin_user, admin_password):
    env = {**os.environ, "PGPASSWORD": admin_password}
    if db_type == "postgresql":
        cmd = ["psql", "-h", host, "-U", admin_user, "-c",
               "SELECT usename, usesuper, usecreatedb, valuntil FROM pg_user;", "--no-align", "-t"]
    elif db_type == "mysql":
        cmd = ["mysql", "-h", host, "-u", admin_user, f"-p{admin_password}", "-e",
               "SELECT user, host, Super_priv, Grant_priv FROM mysql.user;", "-B"]
    else:
        cmd = ["sqlcmd", "-S", host, "-U", admin_user, "-P", admin_password, "-Q",
               "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U');"]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    return [{"raw": line.strip()} for line in result.stdout.strip().split("\n") if line.strip()]


def audit_shared_accounts(users):
    shared_patterns = ["admin", "dba", "root", "sa", "dbadmin", "sysadmin"]
    findings = []
    for user in users:
        raw = user.get("raw", "").lower()
        for pattern in shared_patterns:
            if pattern in raw:
                findings.append({"user": raw, "issue": f"Potential shared account ({pattern})", "severity": "high"})
    return findings


def audit_session_logging(db_type, host, admin_user, admin_password):
    findings = []
    env = {**os.environ, "PGPASSWORD": admin_password}
    if db_type == "postgresql":
        cmd = ["psql", "-h", host, "-U", admin_user, "-c", "SHOW log_connections;", "--no-align", "-t"]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
        if "off" in result.stdout.lower():
            findings.append({"issue": "log_connections disabled", "severity": "high"})
    return findings


def check_tls(host, port):
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-brief"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {"tls_enabled": "Protocol" in result.stdout or "TLS" in result.stdout}
    except subprocess.TimeoutExpired:
        return {"tls_enabled": False}


def generate_report(users, shared, logging_findings, tls):
    all_findings = shared + logging_findings
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "total_users": len(users), "shared_account_findings": shared,
        "logging_findings": logging_findings, "encryption": tls,
        "total_findings": len(all_findings),
    }


def main():
    parser = argparse.ArgumentParser(description="PAM Database Access Audit Agent")
    parser.add_argument("--db-type", required=False, choices=["postgresql", "mysql", "mssql"])
    parser.add_argument("--host", required=False)
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--admin-user", required=False)
    parser.add_argument("--admin-password", required=False)
    parser.add_argument("--output", default="pam_db_audit_report.json")
    args = parser.parse_args()
    from cold_box_room.skills.script_helpers import patch_args_from_harness
    patch_args_from_harness(args)

    users = query_db_users(args.db_type, args.host, args.admin_user, args.admin_password)
    shared = audit_shared_accounts(users)
    logging_f = audit_session_logging(args.db_type, args.host, args.admin_user, args.admin_password)
    tls = check_tls(args.host, args.port)
    report = generate_report(users, shared, logging_f, tls)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("PAM DB audit: %d users, %d findings", len(users), report["total_findings"])
    print(json.dumps(report, indent=2, default=str))


# cold-box harness entry
def analyze_image(image_path, case_dir):
    from cold_box_room.skills.script_helpers import run_default_analyze_image

    return run_default_analyze_image(
        image_path,
        case_dir,
        skill_slug='cb-implementing-pam-for-database-access',
        main_fn=main,
    )

if __name__ == "__main__":
    main()
