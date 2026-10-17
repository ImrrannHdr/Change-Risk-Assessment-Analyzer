
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
    """
    Main Terraform Risk Assessment function.

    1. Parse Terraform plan.
    2. Analyze IAM changes.
    3. Analyze network changes.
    4. Investigate network blast radius when enabled.
    5. Analyze cost changes.
    6. Analyze rollback risks.
    7. Calculate final risk score and decision.
    """

    print("\n========== RISK ANALYSIS STARTED ==========", flush=True)
    print(f"[RISK] Environment: {environment}", flush=True)
    print(f"[RISK] Region: {region}", flush=True)
    print(f"[RISK] Context enabled: {enable_context}", flush=True)

    # --------------------------------------------------
    # STEP 1: Parse Terraform plan
    # --------------------------------------------------

    changes = parse_tfplan(plan)
    findings = []

    print(
        f"[RISK] Total Terraform resource changes: {len(changes)}",
        flush=True,
    )

    # --------------------------------------------------
    # STEP 2: IAM risk analysis
    # --------------------------------------------------

    print("\n[STEP 2] Starting IAM analysis", flush=True)

    iam_findings = iam.analyze(changes)
    findings.extend(iam_findings)

    print(f"[IAM] Total findings: {len(iam_findings)}", flush=True)

    for finding in iam_findings:
        print(
            f"[IAM] Category={finding.category} | "
            f"Resource={finding.resource} | "
            f"Severity={finding.severity} | "
            f"Points={finding.risk_points} | "
            f"Message={finding.message}",
            flush=True,
        )

    # --------------------------------------------------
    # STEP 3: Network risk analysis
    # --------------------------------------------------

    print("\n[STEP 3] Starting Network analysis", flush=True)

    network_findings = network.analyze(
        changes,
        plan=plan,
    )

    print(
        f"[NETWORK] Total findings: {len(network_findings)}",
        flush=True,
    )

    # Print the actual findings returned by network.analyze().
    for finding in network_findings:
        print(
            f"[NETWORK] Category={finding.category} | "
            f"Resource={finding.resource} | "
            f"Severity={finding.severity} | "
            f"Points={finding.risk_points} | "
            f"Message={finding.message}",
            flush=True,
        )

    # --------------------------------------------------
    # STEP 4: Optional context-aware analysis
    # --------------------------------------------------

    print("\n[STEP 4] Context-aware investigation", flush=True)

    if enable_context:

        print("[CONTEXT] Context analysis ENABLED", flush=True)

        for finding in network_findings:

            # Only INTERNET_EXPOSURE findings currently
            # trigger blast-radius investigation.
            if finding.category != "INTERNET_EXPOSURE":
                print(
                    f"[CONTEXT] Skipping {finding.resource} | "
                    f"Category={finding.category}",
                    flush=True,
                )
                continue

            print(
                f"[CONTEXT] Investigating blast radius for: "
                f"{finding.resource}",
                flush=True,
            )

            try:
                # Resolve the security group and discover:
                # - Planned Terraform EC2 dependencies
                # - Existing AWS EC2 instances
                # - Existing AWS network interfaces
                context = analyze_security_group_impact(
                    plan=plan,
                    rule_address=finding.resource,
                    region=region,
                    resource_collector=resource_collector,
                )

                # Add the context information to the
                # original network finding's evidence.
                finding.evidence["blast_radius"] = context

                print(
                    f"[CONTEXT] Investigation status: "
                    f"{context.get('status')}",
                    flush=True,
                )

                print(
                    f"[CONTEXT] Security group ID: "
                    f"{context.get('security_group_id')}",
                    flush=True,
                )

                print(
                    f"[CONTEXT] Security group address: "
                    f"{context.get('security_group_address')}",
                    flush=True,
                )

                print(
                    f"[CONTEXT] Context complete: "
                    f"{context.get('context_complete')}",
                    flush=True,
                )

                # --------------------------------------
                # Planned Terraform dependencies
                # --------------------------------------

                planned = context.get("planned_dependencies")

                if planned is not None:
                    print(
                        f"[CONTEXT] Planned dependency count: "
                        f"{planned.get('resource_count')}",
                        flush=True,
                    )

                    for resource in planned.get(
                        "affected_resources", []
                    ):
                        print(
                            f"[CONTEXT] Planned affected resource: "
                            f"{resource.get('address')}",
                            flush=True,
                        )
                else:
                    print(
                        "[CONTEXT] Planned dependencies not determined",
                        flush=True,
                    )

                # --------------------------------------
                # Existing AWS dependencies
                # --------------------------------------

                existing = context.get("existing_dependencies")

                if existing is not None:
                    print(
                        f"[CONTEXT] Existing EC2 count: "
                        f"{existing.get('instance_count')}",
                        flush=True,
                    )

                    print(
                        f"[CONTEXT] Existing EC2 IDs: "
                        f"{existing.get('ec2_instances')}",
                        flush=True,
                    )

                    print(
                        f"[CONTEXT] Network interface count: "
                        f"{existing.get('network_interface_count')}",
                        flush=True,
                    )

                    print(
                        f"[CONTEXT] Public IP detected: "
                        f"{existing.get('public_ip_detected')}",
                        flush=True,
                    )
                else:
                    print(
                        "[CONTEXT] Existing AWS dependencies "
                        "not determined",
                        flush=True,
                    )

            except Exception as error:

                # Discovery failure must NOT mean
                # that no AWS resources are affected.
                print(
                    f"[CONTEXT] ERROR investigating "
                    f"{finding.resource}: {error}",
                    flush=True,
                )

                # Print traceback to CloudWatch.
                traceback.print_exc()

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

    else:
        print(
            "[CONTEXT] Context analysis DISABLED",
            flush=True,
        )

    # --------------------------------------------------
    # STEP 5: Add Network findings
    # --------------------------------------------------

    # Network findings may now contain blast-radius evidence.
    findings.extend(network_findings)

    print(
        f"[RISK] IAM + Network findings: {len(findings)}",
        flush=True,
    )

    # --------------------------------------------------
    # STEP 6: Cost analysis
    # --------------------------------------------------

    print("\n[STEP 6] Starting Cost analysis", flush=True)

    cost_findings = cost.analyze(changes)
    findings.extend(cost_findings)

    print(
        f"[COST] Total findings: {len(cost_findings)}",
        flush=True,
    )

    for finding in cost_findings:
        print(
            f"[COST] Category={finding.category} | "
            f"Resource={finding.resource} | "
            f"Points={finding.risk_points} | "
            f"Message={finding.message}",
            flush=True,
        )

    # --------------------------------------------------
    # STEP 7: Rollback analysis
    # --------------------------------------------------

    print("\n[STEP 7] Starting Rollback analysis", flush=True)

    rollback_findings = rollback.analyze(changes)
    findings.extend(rollback_findings)

    print(
        f"[ROLLBACK] Total findings: {len(rollback_findings)}",
        flush=True,
    )

    for finding in rollback_findings:
        print(
            f"[ROLLBACK] Category={finding.category} | "
            f"Resource={finding.resource} | "
            f"Points={finding.risk_points} | "
            f"Message={finding.message}",
            flush=True,
        )

    # --------------------------------------------------
    # STEP 8: Print summary of all findings
    # --------------------------------------------------

    print("\n========== FINDINGS SUMMARY ==========", flush=True)

    print(f"[SUMMARY] IAM: {len(iam_findings)}", flush=True)
    print(f"[SUMMARY] Network: {len(network_findings)}", flush=True)
    print(f"[SUMMARY] Cost: {len(cost_findings)}", flush=True)
    print(f"[SUMMARY] Rollback: {len(rollback_findings)}", flush=True)
    print(f"[SUMMARY] Total findings: {len(findings)}", flush=True)

    # Display the individual findings included in scoring.
    for index, finding in enumerate(findings, start=1):
        print(
            f"[FINDING-{index}] "
            f"Category={finding.category} | "
            f"Resource={finding.resource} | "
            f"Severity={finding.severity} | "
            f"Risk points={finding.risk_points} | "
            f"Message={finding.message}",
            flush=True,
        )

    # --------------------------------------------------
    # STEP 9: Final risk evaluation
    # --------------------------------------------------

    print("\n[STEP 9] Evaluating final risk", flush=True)

    result = evaluate(
        findings,
        environment=environment,
    )

    print("\n========== FINAL RESULT ==========", flush=True)

    print(f"[RESULT] Risk score: {result.risk_score}", flush=True)
    print(f"[RESULT] Risk level: {result.risk_level}", flush=True)
    print(f"[RESULT] Decision: {result.decision}", flush=True)

    print("========== ANALYSIS COMPLETED ==========\n", flush=True)

    return result
