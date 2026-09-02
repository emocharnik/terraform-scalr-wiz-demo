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

| Directory | Intent | Headline findings |
|---|---|---|
| `00-clean-baseline` | **clean** | — (encrypted, private, versioned, logged) |
| `01-public-storage` | **critical** | Public bucket policy, all four public-access blocks off, public ACL, no encryption, no versioning, mutable ECR tags |
| `02-network-exposure` | **critical** | SSH/RDP/MySQL open to `0.0.0.0/0`, all-ports open to `::/0`, publicly accessible RDS, plaintext HTTP listener, no VPC flow logs, hardcoded DB password |
| `03-unencrypted-data` | **high** | Unencrypted EBS/RDS/EFS/SQS/SNS/DynamoDB, zero backup retention, no deletion protection |
| `04-iam-overprivileged` | **critical** | `Action:*` on `Resource:*`, role assumable by `AWS:"*"`, AdministratorAccess attached, static access key, unrestricted `iam:PassRole` |
| `05-low-severity-only` | **low/medium only** | Missing tags, no lifecycle rule, no detailed monitoring, IMDSv2 optional |
| `06-remediated` | **clean** | Scenarios 01–04 rebuilt correctly — the before/after payoff |
| `07-critical-exposure` | **maximum** | Anonymous `s3:*` + public-read-write ACL, public AMI, public policies on Secrets Manager / ECR / SQS, internet-facing unencrypted Redshift, OpenSearch with anonymous `es:*`, EKS API open to `0.0.0.0/0`, weak password policy |

Each `main.tf` opens with a comment listing exactly which findings are planted
and why that scenario is useful, so you can read it aloud off the screen.

> **Whether a scenario blocks the run is decided by your Wiz CI/CD scan policy,
> not by this repo.** These scenarios plant the findings; your Wiz policy decides
> which of them fail. A connection with no IaC scan policy attached will report
> `PASSED_BY_POLICY` on every scenario here, including `02`. Do the verification
> step below before demoing — it takes one run.

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

### 1a. Make Wiz actually fail on IaC — do not skip this

**The Wiz built-in defaults will not block anything.** Confirmed by inspecting a
real policy input, the stock `Default IaC policy` ships as:

```
params.severityThreshold    = "CRITICAL"
policyLifecycleEnforcements = [ {CLI, AUDIT}, {CODE, AUDIT}, {ADMISSION_CONTROLLER, AUDIT} ]
```

Two independent reasons nothing fails:

1. **`severityThreshold: CRITICAL`** discards every finding below Critical.
   Most Terraform misconfiguration rules are rated High or lower, so in practice
   everything is dropped.
2. **`enforcementMethod: AUDIT`** on the CLI lifecycle means the policy reports
   but never fails the scan. Compare `Default vulnerabilities policy`, which is
   `BLOCK`.

Measured on scenarios in this repo against those defaults:

| Scenario | IaC findings | Failed policies | Verdict |
|---|---|---|---|
| `02-network-exposure` | 86 | none | `PASSED_BY_POLICY` |
| `04-iam-overprivileged` | 15 | none | `PASSED_BY_POLICY` |

The tell in the run output is `IaC (N filtered)` alongside an empty
`Failed Policies:` line.

**Filtered findings are gone, not hidden.** They are discarded before the result
is serialised, so `run_tasks.wiz.result.iac.ruleMatches` is `null` and every
counter in `scanStatistics` reads `0`. No OPA policy can recover them. This must
be fixed in Wiz — there is no Scalr-side workaround.

#### The fix

In Wiz, create a CI/CD scan policy (cloning rather than editing the built-in
keeps other pipelines untouched):

- Type: **IaC**
- `severityThreshold`: **LOW** (or MEDIUM — anything below CRITICAL)
- CLI enforcement: **BLOCK** for auto-fail mode, or leave **AUDIT** if you intend
  to enforce through OPA instead
- Name: something stable, e.g. `Scalr Demo IaC`

Then put that exact display name in the connection's **Default policies** field.
Scalr matches on exact display name; a rename in Wiz breaks scans until updated.

That field is a lookup, not a definition — it selects which policies run, not how
they filter. Leaving it empty uses your tenant defaults. No value typed there can
change a threshold.

#### Finding out which rules are Critical, without Wiz console access

You don't need the Wiz UI to iterate. With `severityThreshold: CRITICAL`, only
Critical findings survive filtering — so the policy input tells you directly
whether you landed any:

1. Run a scenario with the connection in **Policy check** mode.
2. Open the post-plan policy check step and copy the policy input.
3. Read `run_tasks.wiz.result.iac.scanStatistics.criticalMatches`.
   - `> 0` — the findings survived. `result.iac.ruleMatches` names them, and
     `wiz_severity_budget` will block the run even though Wiz is set to AUDIT.
     Your demo works with no Wiz change at all.
   - `0` — nothing in that scenario is rated Critical. Try another, and if
     `07-critical-exposure` also returns 0, stop writing Terraform: the
     threshold itself has to come down.

Measured so far on a stock tenant: `02-network-exposure` 86 findings and
`04-iam-overprivileged` 15 findings, all filtered, zero Critical. Wide-open
security groups and wildcard IAM admin are **not** Critical in Wiz's catalogue,
which is why `07-critical-exposure` reaches for anonymous write access, publicly
shared resources and public resource policies on secrets instead.

#### Choosing where enforcement happens

| | `severityThreshold` | CLI enforcement | Who blocks |
|---|---|---|---|
| Auto-fail | LOW | **BLOCK** | Wiz |
| Policy check + OPA | LOW | AUDIT | Your Rego, via `wiz_severity_budget` |

The second is the better demo: Wiz reports, Scalr decides, and the severity
budget is yours to tune live. Either way `severityThreshold` must come down —
that is the non-negotiable change.

`wiz_integration_hygiene` (enabled by default) detects both misconfigurations
and fails the run with an explanation, so you find out during setup rather than
mid-demo.

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
   Wiz fails the run post-plan and apply is never offered. (If it passes
   instead, your Wiz policy isn't failing IaC findings — see step 1a.)
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
| `wiz_integration_hygiene` | enabled | hard-mandatory | Fails the run if the evaluated Wiz policies can't stop a bad plan: no IaC policy, `severityThreshold` above HIGH, or CLI enforcement set to AUDIT. |
| `wiz_verdict` | enabled | hard-mandatory | Blocks on `FAILED_BY_POLICY`, `ERRORED`, `UNREACHABLE`, or a missing result. Fails closed — an unverified plan is not a passing plan. |
| `wiz_severity_budget` | disabled | soft-mandatory | Grades findings against a per-severity budget. Critical/High block; Medium/Low tolerated up to a limit. |
| `wiz_break_glass` | disabled | hard-mandatory | Blocks Wiz failures unless the workspace carries the `wiz-break-glass` tag — and never honours that tag in production. |

Two implementation notes worth knowing before you're asked:

**The pre-plan guard.** `input.run_tasks` only exists post-plan. Every policy is
gated on `input.tfplan` being present, so a pre-plan evaluation stays silent
instead of blocking the run before Wiz has had a chance to scan.

**The schema, verified.** Captured from a real run rather than assumed:

```
run_tasks.wiz.status.verdict                     PASSED_BY_POLICY | FAILED_BY_POLICY | ERRORED | UNREACHABLE
run_tasks.wiz.status.state                       SUCCESS | ...
run_tasks.wiz.result.iac.ruleMatches             findings, or null when filtered
run_tasks.wiz.result.iac.failedPolicyMatches     null when nothing failed
run_tasks.wiz.result.iac.scanStatistics          {critical,high,medium,low,info}Matches, totalMatches
run_tasks.wiz.policies[]                         .name .type .params.severityThreshold
                                                 .policyLifecycleEnforcements[]{enforcementMethod,deploymentLifecycle}
tfrun.workspace.tags                             ARRAY (older Scalr examples show an object)
tfrun.workspace.environment_type                 production | staging | testing | development | unmapped
```

`wiz_severity_budget` reads the `scanStatistics` counters directly.
`wiz_break_glass` accepts all three tag shapes (`["name"]`, `[{"name":…}]`, and
the legacy `{"name":""}`) because the array element type isn't documented.

To re-capture after a Wiz or Scalr upgrade: run a scenario in policy-check mode,
open the post-plan policy check step, copy the policy input, and rebuild the
mocks from it. Captured inputs are gitignored — they carry account IDs, user
emails and Wiz report URLs.

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

## Troubleshooting

**Every scenario returns `PASSED_BY_POLICY`.** The scan is working but no IaC
policy is failing findings. See setup step 1a — look for `IaC (N filtered)` in
the scan summary.

Measured on a tenant using the stock `Default IaC policy`, with that policy
confirmed present in `Evaluated Policies`:

| Scenario | IaC findings | Failed policies |
|---|---|---|
| `02-network-exposure` | 86 | none |
| `04-iam-overprivileged` | 15 | none |

Both filtered entirely, across two different rule classes. If you see this, the
scenarios are working and the threshold on the Wiz side is the cause — no
change to the Terraform or to Scalr's settings will produce a block. Note also
that naming policies in the connection's **Default policies** field does not
help: it selects which policies run, not how they filter.

**`Verdict: PASSED_BY_POLICY` but `Failed Policies:` is empty and you expected a
block.** Same cause. Note that `wiz_verdict` is a deny-list: it blocks on
`FAILED_BY_POLICY`, `ERRORED` and `UNREACHABLE` only, so a passing verdict
correctly produces no denial. The policy is not the problem here.

**The post-plan policy check step doesn't appear.** The policy group isn't
linked to the environment, or the Wiz connection is in auto-fail mode rather than
policy-check mode.

**Policies fail to load with a parse error.** The policy group's OPA version is
below 0.59; `import rego.v1` isn't recognised.

**Scans fail after working previously.** A Wiz scan policy was renamed. Scalr
matches display names exactly — update the name on the connection.

---

## Notes

- Verdict strings observed from real runs: `PASSED_BY_POLICY`,
  `FAILED_BY_POLICY`, `ERRORED`, `UNREACHABLE`.
- There is no `scalr_wiz_integration` resource in the Scalr Terraform provider —
  the Wiz connection is configured in the UI or via the API.
- The hardcoded passwords in `02` and `03` are intentional, not oversights.
  They are fake and those scenarios can never be applied. Note that Wiz's
  secrets scanner did not flag them in testing — an inline `password =` on an
  `aws_db_instance` shows up as an IaC finding, not a secrets finding. Don't
  promise a secrets detection you haven't seen fire on your own tenant.
- `06-remediated` uses `manage_master_user_password` so the remediated database
  has no credential in source at all.
