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

### 1a. Verify Wiz actually fails on IaC — do not skip this

The scan policies you name on the Scalr connection are what decide pass/fail.
The Wiz defaults lean towards vulnerabilities, SAST and malware; **if no IaC
scan policy is evaluated, or its severity threshold filters everything, every
scenario in this repo reports `PASSED_BY_POLICY` and nothing ever blocks.**

Run `02-network-exposure` once and read the Wiz step's scan summary:

```
No results found:  IaC (86 filtered), SAST, OS packages, ...
Verdict: PASSED_BY_POLICY
Failed Policies:
```

`IaC (86 filtered)` is the tell. Wiz found 86 IaC findings and then discarded
every one of them, so no policy failed. What you want instead is a non-empty
`Failed Policies:` line and `Verdict: FAILED_BY_POLICY`.

Check `Evaluated Policies` on that same summary first:

- **No IaC policy listed** — add one to the scan policy list on the Scalr Wiz
  connection. Scalr matches on **exact display name**, so a policy renamed in
  Wiz breaks scans until the connection is updated.
- **`Default IaC policy` is listed and findings are still filtered** — this is
  the common case. The policy is evaluating, but its matching criteria exclude
  your findings. Wiz's stock IaC policy sits at a high severity threshold, and
  most Terraform misconfiguration rules are rated High or below, so everything
  gets discarded.

To fix the second case, open the `Wiz Cloud Event` link from the run output. It
lists the findings Wiz actually recorded and their severities — that tells you
precisely where the threshold needs to sit. Then either:

- **Lower the threshold on `Default IaC policy`** to at or below the highest
  severity in that list, or
- **Create a demo-specific CI/CD scan policy** (recommended — it leaves your
  real policy untouched): type IaC, severity threshold at or below your
  findings, action set to fail the scan. Name it something stable like
  `Scalr Demo IaC policy` and add that exact display name to the Scalr
  connection.

The second option is worth the extra two minutes: you get a policy tuned for the
demo without loosening a control that other pipelines depend on.

The connection's **Default policies** field is a lookup by exact display name,
not a place to define behaviour. Leaving it empty uses your tenant's default
CI/CD policies; naming policies scopes the scan to exactly those, which also
strips vulnerability/SAST/malware noise from the run output. No value typed here
can change a policy's severity threshold.

#### If you have no access to the Wiz console

1. Try `01-public-storage` and `04-iam-overprivileged` before concluding the
   threshold is the problem. They plant data-exposure and identity-escalation
   findings, which Wiz rates higher than the network misconfigurations in `02`.
   One of them may clear a threshold that `02` cannot.
2. Switch the connection to **Policy check** mode, run a failing scenario, and
   open the policy input on the post-plan policy check step. If the filtered
   findings are present in `input.run_tasks.wiz` despite the passing verdict,
   `wiz_severity_budget` can enforce on them directly and you need no Wiz change
   at all — which is arguably the better story: the Wiz policy is tuned for
   another pipeline, and Scalr still gates the deploy. If they are stripped, you
   will see that immediately and know Wiz access is required.

Only once `02` returns `FAILED_BY_POLICY` with a non-empty `Failed Policies:`
line is the demo ready.

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

## Troubleshooting

**Every scenario returns `PASSED_BY_POLICY`.** The scan is working but no IaC
policy is failing findings. See setup step 1a — look for `IaC (N filtered)` in
the scan summary.

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
