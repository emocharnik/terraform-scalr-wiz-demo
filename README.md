# Wiz + Scalr demo

Terraform scenarios and OPA policies for demonstrating Scalr's Wiz integration.

Scalr runs a Wiz scan **after** `terraform plan` and **before** the run can
continue to apply. Each directory under `scenarios/` is a plan that is perfectly
valid Terraform but carries a different security posture, so you can show the
Wiz step passing, blocking, and grading findings by severity.

**Nothing here can touch a real AWS account.** Every scenario uses fake
credentials and skips the AWS API pre-flight checks, so `terraform plan`
produces a complete plan without ever calling AWS — which is all Wiz needs,
since it scans the exported plan JSON. See the comment block in any
`providers.tf` for how to point a scenario at a real account instead.

---

## Scenarios

| Directory | Expected Wiz verdict | Headline findings |
|---|---|---|
| `00-clean-baseline` | **PASSED** | — (encrypted, private, versioned, logged) |
| `01-public-storage` | **FAILED_BY_POLICY** — Critical | Public bucket policy, all four public-access blocks off, public ACL, no encryption, no versioning, mutable ECR tags |
| `02-network-exposure` | **FAILED_BY_POLICY** — Critical | SSH/RDP/MySQL open to `0.0.0.0/0`, all-ports open to `::/0`, publicly accessible RDS, plaintext HTTP listener, no VPC flow logs, hardcoded DB password |
| `03-unencrypted-data` | **FAILED_BY_POLICY** — High | Unencrypted EBS/RDS/EFS/SQS/SNS/DynamoDB, zero backup retention, no deletion protection |
| `04-iam-overprivileged` | **FAILED_BY_POLICY** — Critical | `Action:*` on `Resource:*`, role assumable by `AWS:"*"`, AdministratorAccess attached, static access key, unrestricted `iam:PassRole` |
| `05-low-severity-only` | **FAILED_BY_POLICY** — Low/Medium only | Missing tags, no lifecycle rule, no detailed monitoring, IMDSv2 optional |
| `06-remediated` | **PASSED** | Scenarios 01–04 rebuilt correctly — the before/after payoff |

Each `main.tf` opens with a comment listing exactly which findings are planted
and why that scenario is useful, so you can read it aloud off the screen.

> Severity assignment belongs to **your** Wiz CI/CD scan policy, not to this
> repo. Scenario 05 in particular assumes your policy rates those items as
> Low/Medium. Run it once against your own tenant and confirm before demoing.

---

## One-time setup

### 1. Connect Wiz to Scalr

Account scope → **Integrations** → **Wiz**. You need a Wiz service account with
the `create:security_scans` permission, plus its client ID and secret, and
`integrations:manage` in Scalr. Scalr supports one Wiz connection per account.

Choose the enforcement mode:

- **Auto-fail** — Scalr blocks the run whenever Wiz reports a policy failure or
  the scan can't complete. No Rego needed. Warnings don't block.
- **Policy check** — the validated Wiz result is published to
  `input.run_tasks.wiz` in the post-plan policy input, and your OPA policies
  decide. This is what `policies/wiz/` is for.

Scope the connection to the environment you're demoing in. Self-hosted agents
need Scalr Agent 1.3.0+.

### 2. Create the workspaces

One workspace per scenario, all pointing at this repo:

- **Working directory**: `scenarios/<scenario-name>`
- **Auto-apply**: **off** — you never want an insecure plan applying itself
- **Type**: `development`

For the break-glass demo you'll also want one extra workspace on
`scenarios/01-public-storage` with **Type: `production`**, which lets you show
that the exception tag is ignored in prod.

### 3. Create the policy group (policy-check mode only)

Point a policy group at this repo with path `policies/wiz`, and set the OPA
version to **0.59 or newer** — the policies use `import rego.v1`. Link it to the
demo environment.

`policies/wiz/scalr-policy.hcl` ships with `wiz_verdict` enabled and the other
two disabled, which is the right starting state: it reproduces auto-fail
behaviour so you can introduce one idea at a time.

---

## Demo flows

### A. The core loop — 5 minutes

1. Run **`00-clean-baseline`**. Plan succeeds, Wiz step green, apply available.
   Establishes the scan is real before you show it catching anything.
2. Run **`01-public-storage`**. Plan still succeeds — *this is the moment*.
   The Terraform is valid; nothing in the plan output says "public bucket".
   Wiz fails the run post-plan and apply is never offered.
3. Open the Wiz step and walk the findings.
4. Run **`06-remediated`**. Green. Diff it against `01` to show the fix is
   ordinary code review, not a security ticket.

### B. Why policy-check beats auto-fail — 4 minutes

Run **`05-low-severity-only`** twice, changing nothing in the Terraform:

1. With only `wiz_verdict` enabled → **blocked**. Wiz said FAILED_BY_POLICY, so
   the run stops, even though every finding is minor.
2. Enable `wiz_severity_budget` in `scalr-policy.hcl`, push, re-run → **passes**.
   Same Wiz result, different business outcome, decided by your Rego.

Then run `01-public-storage` under the same policy to show Critical still
blocks. The budget lives at the top of `wiz_severity_budget.rego` — edit it live
if someone asks "what if we allowed one High?".

Because that policy is **soft-mandatory**, a violation can also be overridden by
an approver on the run, which gives you the approval flow to show as well.

### C. Governed exceptions — 3 minutes

Enable `wiz_break_glass` and disable `wiz_verdict` (they overlap — the latter
blocks unconditionally).

1. Run **`01-public-storage`** → blocked, with a message naming the tag needed.
2. Add the `wiz-break-glass` tag to the workspace, re-run → passes. The
   exception is explicit, attributable, and recorded in workspace history.
3. Run the **production** workspace on the same code, with the same tag →
   still blocked. Exceptions are never honoured in production.

This is the answer to "what happens when we genuinely need to ship anyway?"

---

## Policies

All three live in `policies/wiz/`, each with mock inputs and `opa test` tests.

| Policy | Default | Enforcement | Behaviour |
|---|---|---|---|
| `wiz_verdict` | enabled | hard-mandatory | Blocks on `FAILED_BY_POLICY`, `ERRORED`, `UNREACHABLE`, or a missing result. Fails closed — an unverified plan is not a passing plan. |
| `wiz_severity_budget` | disabled | soft-mandatory | Grades findings against a per-severity budget. Critical/High block; Medium/Low tolerated up to a limit. |
| `wiz_break_glass` | disabled | hard-mandatory | Blocks Wiz failures unless the workspace carries the `wiz-break-glass` tag — and never honours that tag in production. |

Two implementation notes worth knowing before you're asked:

**The pre-plan guard.** `input.run_tasks` only exists post-plan. Every policy is
gated on `input.tfplan` being present, so a pre-plan evaluation stays silent
instead of blocking the run before Wiz has had a chance to scan.

**The nested schema.** Scalr documents `status.verdict` as stable but notes that
Wiz owns the nested result schema. `wiz_verdict` and `wiz_break_glass` read only
`status.verdict`. `wiz_severity_budget` needs severities, so it *walks* the
result collecting any object with a `severity` field, skipping ones marked
passed. That's deliberately tolerant, and counts can double-count a result that
repeats severity at both rule and match level. Before relying on exact numbers:

1. Run a failing scenario with the policy group linked.
2. Open the run's policy check step and copy the real policy input.
3. Paste it into `wiz_severity_budget_mock.json`, replacing the placeholder.
4. Tighten the walk into a direct path and re-run `opa test`.

---

## Rehearsing locally

```bash
./scripts/rehearse.sh
```

Runs `opa test` over the policies, plans every scenario, and writes the plan
JSON that Scalr would hand to Wiz. If `wizcli` is installed and authenticated it
also scans each scenario, so you can confirm findings and severities against
your own Wiz policy before you're in front of an audience.

One scenario at a time:

```bash
./scripts/rehearse.sh 01-public-storage
```

Policies only:

```bash
opa test policies/wiz/ -v --format pretty
```

Requires OPA 0.59+ (for `import rego.v1`) and Terraform 1.5+ or OpenTofu
(`TF_BIN=tofu ./scripts/rehearse.sh`). CI runs both checks on every push.

---

## Notes

- There is no `scalr_wiz_integration` resource in the Scalr Terraform provider —
  the Wiz connection is configured in the UI or via the API.
- The hardcoded passwords in `02` and `03` are intentional findings, not
  oversights. They are fake, and those scenarios can never be applied.
- `06-remediated` uses `manage_master_user_password` so the remediated database
  has no credential in source at all.
