
from typing import Callable
import traceback

from src.analyzers import cost, iam, network, rollback
from src.parser import parse_tfplan
from src.risk_engine import evaluate
from src.context.impact_orchestrator import analyze_all_sg_changes
from src.context.route_reporting import analyze_route_impacts


def analyze_plan(
    plan: dict,
    environment: str = "dev",
    enable_context: bool = False,
    resource_collector: Callable | None = None,
    region: str = "ap-southeast-2",
    impact_sink: list[dict] | None = None,
    enable_route_context: bool = False,
    route_impact_sink: list[dict] | None = None,
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
    # STEP 4: Independent SG impact discovery.
    # Run on ALL SG changes, not only INTERNET_EXPOSURE findings.
    # Do NOT append impact records to scored findings.
    # --------------------------------------------------

    if enable_context:
        print("[IMPACT] Starting independent SG impact scan", flush=True)
        impact_records = analyze_all_sg_changes(
            plan=plan,
            region=region,
            resource_collector=resource_collector,
        )
        print(f"[IMPACT] Completed {len(impact_records)} records", flush=True)
        # Optional caller-owned list for Lambda handler persistence.
        # Do not change AnalysisResult's return type / risk score.
        if impact_sink is not None:
            impact_sink.extend(impact_records)
    else:
        print("[IMPACT] Context analysis disabled", flush=True)

    # Stage 3D: Independent advisory-only route analysis.
    # Do not add route records to scored findings or change evaluate().
    if enable_route_context:
        print("[ROUTE-IMPACT] Starting route context assessment", flush=True)
        route_records = analyze_route_impacts(plan, region=region)
        if route_impact_sink is not None:
            route_impact_sink.extend(route_records)
        print(f"[ROUTE-IMPACT] Completed {len(route_records)} records", flush=True)
    else:
        print("[ROUTE-IMPACT] Disabled", flush=True)

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
