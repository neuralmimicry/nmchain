Overview: Improve NMChain through the Conductor execution loop.

Delivery Context:
- Current stage: development
- Validated stages: none
- Rollout strategy: canary

Requirements Register:
- REQ-001: Inspect and record current repository, runtime, or job evidence before selecting an operation.
- REQ-002: Implement only the scoped change, job update, or progress-monitoring action supported by that evidence.
- REQ-003: Preserve secure, resilient behaviour and avoid destructive commands.
- REQ-004: Update or add tests covering the changed path, or provide the relevant live operational check.
- REQ-005: Run verification commands and report the outcome.
- REQ-006: Leave unrelated files untouched.
- REQ-007: Record rollback/recovery steps and the acceptance signal proving the gap is closed.
- REQ-008: Preserve staged progression and rollout governance metadata.
- REQ-009: Capture a fresh protected-target readiness baseline before any change.
- REQ-010: Use the selected canary or red-green rollout strategy and verify the post-rollout health window.
- REQ-011: Automatically revert the exact produced commit without rewriting history if health or verification degrades.
- REQ-012: Verify rollback readiness and recovery before finalising the delivery.
- REQ-013: When runtime rollout or restart work is needed, use the available Ansible automation context: {"ansible_root":"/srv/swarmhpc/ansible","config_path":"/srv/swarmhpc/ansible/ansible.cfg","host_targets":["rk1"],"hosts":["spirit"],"inventory_path":"/srv/swarmhpc/ansible/inventory/hosts.ini","playbooks":["continuum_tenant_nmchain_site.yml"],"repo_root":"/srv/swarmhpc","roles_path":"/srv/swarmhpc/ansible/roles","secrets_root":"/srv/swarmhpc/ansible/.secrets"}.

Work Item Summary:
nmchain is linked to live services but no obvious test capability was discovered in the repository inventory. Establish at least a minimal regression or smoke-test baseline before deeper autonomous changes.

Authoritative delivery constraints (mandatory; implement and verify these, do not merely describe them):
- No structured delivery constraints were supplied; follow the work-item summary exactly.

Plan JSON:
{"action":"establish_repository_test_baseline","finding_id":"29accd83-6c42-477e-ab88-64bfedf86891","finding_key":"repository_test_baseline:neuralmimicry/nmchain","linked_services":["nmchain"],"repository":"neuralmimicry/nmchain"}

Planner guidance (advisory; it must not weaken or contradict the authoritative work-item requirements):
Overview: This work item establishes a test baseline for the nmchain service, which is linked to live services but currently lacks executable project-native validation. The baseline will enable safe autonomous changes by verifying repository, runtime, and job health before deeper delivery actions.

Requirements Register:
- REQ-001: Inspect the nmchain repository at /srv/neuralmimicry/nmchain to confirm path accessibility, branch state, and test coverage gaps.
- REQ-002: Verify local K3s cluster connectivity and worker node probes using kubectl get nodes.
- REQ-003: Review service health logs and metrics on host 'spirit' to identify degradation causes or operational context.
- REQ-004: Validate Ansible syntax and inventory without applying changes using --check mode on the site playbook.
- REQ-005: Ensure codebase health through cargo fmt --check and cargo check commands.
- REQ-006: Execute cargo test --quiet to run the local test suite and capture baseline coverage metrics.
- REQ-007: Implement a staged canary rollout on host 'rk1' to validate runtime behaviour in a controlled environment.
- REQ-008: Monitor post-rollout readiness health window for degradation signals and prepare automatic rollback procedures.
- REQ-009: Preserve existing runtime behaviour and avoid destructive commands during verification.
- REQ-010: Document verification results and update the test baseline registry with coverage and stability metrics.

Rollout Strategy: Canary deployment on host 'rk1' with continuous monitoring for degradation.
Risk Level: Low (verification only, no destructive changes)


Protected rollout contract (mandatory): capture a fresh readiness baseline before any change; use the selected canary or red_green strategy; verify health throughout the post-rollout window; if health or verification degrades, automatically revert the exact produced commit without rewriting history, rerun tests and GitHub Actions, and verify recovery.