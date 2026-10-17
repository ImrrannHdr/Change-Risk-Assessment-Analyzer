"""Terraform plan risk orchestration with CloudWatch-friendly debug messages."""

from typing import Callable
import traceback

from src.analyzers import cost, iam, network, rollback
from src.parser import parse_tfplan
from src.risk_engine import evaluate
from src.context.blast_radius import analyze_security_group_impact


def analyze_plan(
    plan: dict,
    environment: str = "dev",
    enable_context: bool = False,
    resource_collector: Callable | None = None,
    region: str = "ap-southeast-2",
):
    """Analyze Terraform changes; optionally enrich internet-exposure findings.

    Debug output is written to stdout (CloudWatch Logs when deployed in Lambda).
    Context evidence adds information but does not change risk points here.
    """

    print("\n========== TERRAFORM RISK ASSESSMENT STARTED ==========", flush=True)
    print(f"[RISK-ANALYZER] Environment: {environment}", flush=True)
    print(f"[RISK-ANALYZER] AWS region: {region}", flush=True)
    print(f"[RISK-ANALYZER] Context analysis enabled: {enable_context}", flush=True)

    # Step 1: Parse the Terraform plan into Change objects.
    changes = parse_tfplan(plan)
    print(f"[RISK-ANALYZER] Parsed changes: {len(changes)}", flush=True)
    for change in changes:
        print(f"[RISK-ANALYZER] Change resource: {change.address}", flush=True)

    findings = []

    # Step 2: Evaluate IAM changes and append their findings.
    iam_findings = iam.analyze(changes)
    findings.extend(iam_findings)
    print(f"[RISK-ANALYZER] IAM findings: {len(iam_findings)}", flush=True)

    # Step 3: Evaluate network changes, preserving the full plan for reference resolution.
    network_findings = network.analyze(changes, plan=plan)
    print(f"[RISK-ANALYZER] Network findings: {len(network_findings)}", flush=True)
    for finding in network_findings:
        print(
            f"[RISK-ANALYZER] Network finding: "
            f"category={finding.category}, resource={finding.resource}, "
            f"severity={finding.severity}, points={finding.risk_points}",
            flush=True,
        )

    # Step 4: Investigate blast radius ONLY for INTERNET_EXPOSURE findings.
    if enable_context:
        print("[RISK-ANALYZER] Starting context investigation", flush=True)
        succeeded = 0
        failed = 0
        skipped = 0

        for finding in network_findings:
            if finding.category != "INTERNET_EXPOSURE":
                skipped += 1
                print(
                    f"[RISK-ANALYZER] Context skipped: "
                    f"{finding.resource} ({finding.category})",
                    flush=True,
                )
                continue

            print(f"[RISK-ANALYZER] Investigating SG impact: {finding.resource}", flush=True)
            try:
                context = analyze_security_group_impact(
                    plan=plan,
                    rule_address=finding.resource,
                    region=region,
                    resource_collector=resource_collector,
                )

                # Store context against the original network Finding object.
                finding.evidence["blast_radius"] = context
                succeeded += 1
                print(
                    f"[RISK-ANALYZER] Context status: {context.get('status')} "
                    f"| complete={context.get('context_complete')}",
                    flush=True,
                )
                print(
                    f"[RISK-ANALYZER] Resolved SG: "
                    f"{context.get('security_group_id')} "
                    f"({context.get('security_group_address')})",
                    flush=True,
                )

                # Report counts and affected Terraform resource addresses, not full plan JSON.
                planned = context.get("planned_dependencies")
                if planned is None:
                    print("[RISK-ANALYZER] Planned dependencies: unknown", flush=True)
                else:
                    print(
                        f"[RISK-ANALYZER] Planned EC2 dependencies: "
                        f"{planned.get('resource_count')}",
                        flush=True,
                    )
                    for dependency in planned.get("affected_resources", []):
                        print(
                            f"[RISK-ANALYZER] Planned EC2: {dependency.get('address')}",
                            flush=True,
                        )

                # AWS discovery reports live ENI and EC2 associations if resolution succeeded.
                existing = context.get("existing_dependencies")
                if existing is None:
                    print("[RISK-ANALYZER] Existing AWS dependencies: unknown", flush=True)
                else:
                    print(
                        f"[RISK-ANALYZER] Existing EC2 count: {existing.get('instance_count')} "
                        f"| ENI count: {existing.get('network_interface_count')} "
                        f"| public IP present: {existing.get('public_ip_detected')}",
                        flush=True,
                    )
                    print(
                        f"[RISK-ANALYZER] Existing EC2 IDs: {existing.get('ec2_instances')}",
                        flush=True,
                    )

            except Exception as error:
                failed += 1
                print(
                    f"[RISK-ANALYZER] CONTEXT_ERROR: {finding.resource}: "
                    f"{type(error).__name__}: {error}",
                    flush=True,
                )
                # Traceback stays in CloudWatch; don't put raw AWS exception into evidence.
                traceback.print_exc()

                # None signals unknown, not zero affected resources.
                finding.evidence["blast_radius"] = {
                    "status": "CONTEXT_ERROR",
                    "context_complete": False,
                    "existing_dependencies": None,
                    "planned_dependencies": None,
                    "message": (
                        "Context investigation failed: "
                        f"{type(error).__name__}"
                    ),
                }

        print(
            f"[RISK-ANALYZER] Context summary: "
            f"succeeded={succeeded}, failed={failed}, skipped={skipped}",
            flush=True,
        )
    else:
        print("[RISK-ANALYZER] Context analysis disabled", flush=True)

    # Step 5: Include enriched network findings in the combined list.
    findings.extend(network_findings)
    print(f"[RISK-ANALYZER] IAM + network findings: {len(findings)}", flush=True)

    # Step 6: Analyze potential cost impact.
    cost_findings = cost.analyze(changes)
    findings.extend(cost_findings)
    print(f"[RISK-ANALYZER] Cost findings: {len(cost_findings)}", flush=True)

    # Step 7: Analyze rollback and destructive-change risk.
    rollback_findings = rollback.analyze(changes)
    findings.extend(rollback_findings)
    print(f"[RISK-ANALYZER] Rollback findings: {len(rollback_findings)}", flush=True)

    # Step 8: Print a concise summary of all findings, including their risk points.
    print(f"[RISK-ANALYZER] TOTAL FINDINGS: {len(findings)}", flush=True)
    for index, finding in enumerate(findings, start=1):
        print(
            f"[RISK-ANALYZER] Finding {index}: "
            f"category={finding.category} | severity={finding.severity} | "
            f"points={finding.risk_points} | resource={finding.resource}",
            flush=True,
        )

    # Step 9: Return the original risk engine's score and decision unchanged.
    result = evaluate(findings, environment=environment)
    print(f"[RISK-ANALYZER] FINAL RISK SCORE: {result.risk_score}", flush=True)
    print(f"[RISK-ANALYZER] FINAL RISK LEVEL: {result.risk_level}", flush=True)
    print(f"[RISK-ANALYZER] FINAL DECISION: {result.decision}", flush=True)
    print("========== TERRAFORM RISK ASSESSMENT FINISHED ==========\n", flush=True)
    return result
