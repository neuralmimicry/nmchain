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
{"action":"establish_repository_test_baseline","finding_id":"360c2881-78e3-47c1-95e7-d71f8f3083ba","finding_key":"repository_test_baseline:nmchain","linked_services":["nmchain"],"repository":"nmchain"}

Planner guidance (advisory; it must not weaken or contradict the authoritative work-item requirements):
This work item establishes a test baseline for the nmchain repository to enable safe autonomous changes. The baseline ensures that live services linked to the repository can be monitored without introducing destructive modifications. A minimal smoke test will be introduced to validate core service health. The plan includes local verification, canary rollout, and automatic rollback capabilities.

Requirements Register:
- REQ-001: A minimal smoke test file must be created in the tests directory to verify core service health.
- REQ-002: The new test must not modify production logic or existing files in the repository.
- REQ-003: Code style compliance must be verified using cargo fmt --check before compilation.
- REQ-004: The baseline must pass local execution via cargo check and cargo test.
- REQ-005: A canary rollout strategy must be configured for linked live services.
- REQ-006: Automatic rollback must be triggered if degradation is detected during the canary phase.
- REQ-007: A protected-target readiness baseline must be confirmed prior to rollout.
- REQ-008: Post-rollout health monitoring must run for a defined window before full acceptance.


Protected rollout contract (mandatory): capture a fresh readiness baseline before any change; use the selected canary or red_green strategy; verify health throughout the post-rollout window; if health or verification degrades, automatically revert the exact produced commit without rewriting history, rerun tests and GitHub Actions, and verify recovery.