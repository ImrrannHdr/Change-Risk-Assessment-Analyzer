
from typing import Any, Callable

from src.analyzers import cost, iam, network, rollback
from src.parser import parse_tfplan
from src.risk_engine import evaluate
from src.context.blast_radius import (
    analyze_security_group_impact,
)


def analyze_plan(
    plan: dict,
    environment: str = "dev",
    enable_context: bool = False,
    resource_collector: Callable | None = None,
    region: str = "ap-southeast-2",
):
    """
    Main Terraform Risk Assessment orchestration function.

    1. Parse Terraform plan changes.
    2. Analyze IAM risks.
    3. Analyze network risks.
    4. Optionally investigate security group blast radius.
    5. Analyze cost risks.
    6. Analyze rollback risks.
    7. Calculate final risk score and deployment decision.
    """

    print(
        "\n========== TERRAFORM RISK ASSESSMENT STARTED ==========",
        flush=True,
    )

    print(
        f"[RISK-ANALYZER] Environment: {environment}",
        flush=True,
    )

    print(
        f"[RISK-ANALYZER] AWS Region: {region}",
        flush=True,
    )

    print(
        f"[RISK-ANALYZER] Context analysis enabled: {enable_context}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 1: Parse the Terraform plan.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] STEP 1: Parsing Terraform plan...",
        flush=True,
    )

    changes = parse_tfplan(plan)

    print(
        f"[RISK-ANALYZER] Terraform plan parsed successfully. "
        f"Total changes: {len(changes)}",
        flush=True,
    )

    # Initialize the collection of risk findings.
    findings = []

    # ---------------------------------------------------------
    # Step 2: Perform IAM risk analysis.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] STEP 2: Starting IAM risk analysis...",
        flush=True,
    )

    iam_findings = iam.analyze(changes)

    findings.extend(iam_findings)

    print(
        f"[RISK-ANALYZER] IAM analysis completed. "
        f"Findings: {len(iam_findings)}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 3: Perform network risk analysis.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] STEP 3: Starting network risk analysis...",
        flush=True,
    )

    # Pass both parsed changes and the complete Terraform plan.
    # The network analyzer may use plan configuration to
    # resolve relationships between Terraform resources.
    network_findings = network.analyze(
        changes,
        plan=plan,
    )

    print(
        f"[RISK-ANALYZER] Network analysis completed. "
        f"Findings: {len(network_findings)}",
        flush=True,
    )

    # Log the discovered network finding categories.
    for finding in network_findings:

        print(
            f"[RISK-ANALYZER] Network finding detected | "
            f"Category: {finding.category} | "
            f"Resource: {finding.resource} | "
            f"Severity: {finding.severity}",
            flush=True,
        )

    # ---------------------------------------------------------
    # Step 4: Optional context-aware blast-radius analysis.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] STEP 4: Checking context analysis configuration...",
        flush=True,
    )

    if enable_context:

        print(
            "[RISK-ANALYZER] Context analysis is ENABLED",
            flush=True,
        )

        # Track investigation outcomes for debugging.
        context_success_count = 0
        context_error_count = 0
        context_skipped_count = 0

        # Investigate network findings individually.
        for finding in network_findings:

            print(
                f"[RISK-ANALYZER] Evaluating context eligibility | "
                f"Resource: {finding.resource} | "
                f"Category: {finding.category}",
                flush=True,
            )

            # Currently, only INTERNET_EXPOSURE findings
            # are eligible for security group impact analysis.
            if finding.category != "INTERNET_EXPOSURE":

                context_skipped_count += 1

                print(
                    f"[RISK-ANALYZER] SKIPPED: Context analysis "
                    f"not applicable for category {finding.category}",
                    flush=True,
                )

                continue

            # -------------------------------------------------
            # Step 4A: Investigate security group blast radius.
            # -------------------------------------------------

            try:

                print(
                    f"[RISK-ANALYZER] Starting blast-radius "
                    f"investigation for: {finding.resource}",
                    flush=True,
                )

                context = analyze_security_group_impact(
                    plan=plan,
                    rule_address=finding.resource,
                    region=region,
                    resource_collector=resource_collector,
                )

                print(
                    f"[RISK-ANALYZER] Blast-radius investigation "
                    f"returned status: {context.get('status')}",
                    flush=True,
                )

                # Enrich the original finding with blast-radius
                # information. This will later be included in
                # the final risk assessment result.
                finding.evidence["blast_radius"] = context

                context_success_count += 1

                print(
                    f"[RISK-ANALYZER] Blast-radius evidence "
                    f"attached to finding: {finding.resource}",
                    flush=True,
                )

                # Display discovered Terraform dependencies.
                planned_dependencies = context.get(
                    "planned_dependencies"
                )

                if planned_dependencies is not None:

                    print(
                        "[RISK-ANALYZER] Planned Terraform "
                        "dependency count: "
                        f"{planned_dependencies.get('resource_count', 0)}",
                        flush=True,
                    )

                else:

                    print(
                        "[RISK-ANALYZER] Planned Terraform "
                        "dependencies: Not determined",
                        flush=True,
                    )

                # Display discovered existing AWS dependencies.
                existing_dependencies = context.get(
                    "existing_dependencies"
                )

                if existing_dependencies is not None:

                    print(
                        "[RISK-ANALYZER] Existing AWS EC2 "
                        "instance count: "
                        f"{existing_dependencies.get('instance_count', 0)}",
                        flush=True,
                    )

                    print(
                        "[RISK-ANALYZER] Existing AWS network "
                        "interface count: "
                        f"{existing_dependencies.get('network_interface_count', 0)}",
                        flush=True,
                    )

                    print(
                        "[RISK-ANALYZER] Public IP detected: "
                        f"{existing_dependencies.get('public_ip_detected', False)}",
                        flush=True,
                    )

                else:

                    print(
                        "[RISK-ANALYZER] Existing AWS dependencies: "
                        "Not determined",
                        flush=True,
                    )

            # -------------------------------------------------
            # Step 4B: Handle context investigation failures.
            # -------------------------------------------------

            except Exception as error:

                context_error_count += 1

                print(
                    f"[RISK-ANALYZER] ERROR: Blast-radius "
                    f"investigation failed for {finding.resource}",
                    flush=True,
                )

                print(
                    f"[RISK-ANALYZER] Exception type: "
                    f"{type(error).__name__}",
                    flush=True,
                )

                print(
                    f"[RISK-ANALYZER] Exception details: {error}",
                    flush=True,
                )

                # Never interpret discovery failure as zero
                # affected AWS resources.
                #
                # None indicates that the impact could not
                # be determined, not that there were no
                # dependencies.
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
                    "[RISK-ANALYZER] CONTEXT_ERROR evidence "
                    "attached to the finding",
                    flush=True,
                )

        # Summarize context investigation outcomes.
        print(
            "[RISK-ANALYZER] Context investigation summary:",
            flush=True,
        )

        print(
            f"[RISK-ANALYZER] Successful investigations: "
            f"{context_success_count}",
            flush=True,
        )

        print(
            f"[RISK-ANALYZER] Failed investigations: "
            f"{context_error_count}",
            flush=True,
        )

        print(
            f"[RISK-ANALYZER] Skipped findings: "
            f"{context_skipped_count}",
            flush=True,
        )

    else:

        print(
            "[RISK-ANALYZER] Context analysis is DISABLED. "
            "Skipping blast-radius investigation.",
            flush=True,
        )

    # ---------------------------------------------------------
    # Step 5: Add network findings to the main collection.
    # ---------------------------------------------------------

    findings.extend(network_findings)

    print(
        f"[RISK-ANALYZER] IAM and Network analysis completed. "
        f"Combined findings: {len(findings)}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 6: Perform cost risk analysis.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] STEP 5: Starting cost risk analysis...",
        flush=True,
    )

    cost_findings = cost.analyze(changes)

    findings.extend(cost_findings)

    print(
        f"[RISK-ANALYZER] Cost analysis completed. "
        f"Findings: {len(cost_findings)}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 7: Perform rollback risk analysis.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] STEP 6: Starting rollback risk analysis...",
        flush=True,
    )

    rollback_findings = rollback.analyze(changes)

    findings.extend(rollback_findings)

    print(
        f"[RISK-ANALYZER] Rollback analysis completed. "
        f"Findings: {len(rollback_findings)}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 8: Calculate overall risk score and decision.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] STEP 7: Calculating final risk score...",
        flush=True,
    )

    print(
        f"[RISK-ANALYZER] Total findings across all analyzers: "
        f"{len(findings)}",
        flush=True,
    )

    # Calculate the risk score and decision using the
    # existing risk engine.
    result = evaluate(
        findings,
        environment=environment,
    )

    # ---------------------------------------------------------
    # Step 9: Log final risk assessment results.
    # ---------------------------------------------------------

    print(
        "[RISK-ANALYZER] Final risk assessment:",
        flush=True,
    )

    print(
        f"[RISK-ANALYZER] Risk score: {result.risk_score}",
        flush=True,
    )

    print(
        f"[RISK-ANALYZER] Risk level: {result.risk_level}",
        flush=True,
    )

    print(
        f"[RISK-ANALYZER] Deployment decision: {result.decision}",
        flush=True,
    )

    print(
        "========== TERRAFORM RISK ASSESSMENT FINISHED ==========\n",
        flush=True,
    )

    return result
