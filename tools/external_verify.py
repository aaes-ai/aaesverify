#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify an evidence-only external evaluation package with the v3 candidate."""

import argparse
import hashlib
import json
import re
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile

SCHEMA = "aaes.external-evaluation-package/1"
FRAMEWORKS = ("langgraph", "crewai", "autogen")
DATA_FILES = (
    "cases.json",
    "configuration.json",
    "dependencies.lock",
    "execution-plan.json",
    "http-transcript.json",
    "limits.json",
    "provider-calls.json",
    "results.json",
    "evidence/MANIFEST.json",
    "evidence/SHA256SUMS",
    "evidence/export.jsonl",
    "evidence/ledger.pub",
    "evidence/records.jsonl",
)
SHARED_PROFILES = {'1.0.0': {'ids': ('read_allowed',
                   'policy_refused',
                   'approval_required',
                   'agent_self_approval_refused',
                   'scripted_operator_approval',
                   'changed_payload_refused',
                   'approved_action_allowed',
                   'duplicate_retry_refused',
                   'uncertain_effect_preserved',
                   'uncertain_retry_refused'),
           'native': 8,
           'kinds': ('runtime',
                     'runtime',
                     'runtime',
                     'approval',
                     'approval',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime')},
 '2.0.0': {'ids': ('read_allowed',
                   'policy_refused',
                   'approval_required',
                   'agent_self_approval_refused',
                   'scripted_operator_approval',
                   'changed_payload_refused',
                   'approved_action_allowed',
                   'duplicate_retry_refused',
                   'uncertain_effect_preserved',
                   'uncertain_retry_refused',
                   'budget_first_allowed',
                   'budget_exhausted_refused',
                   'cross_tenant_task_refused',
                   'cancellation_baseline_allowed',
                   'scripted_task_cancellation',
                   'cancelled_task_refused',
                   'expiry_approval_required',
                   'scripted_approval_expiry',
                   'expired_operator_approval_refused',
                   'expired_approval_cannot_authorize',
                   'scripted_deadline_expiry',
                   'expired_task_refused',
                   'concurrent_duplicate_refused',
                   'scripted_process_restart',
                   'duplicate_after_restart_refused',
                   'uncertain_after_restart_refused',
                   'budget_after_restart_refused',
                   'crash_after_simulated_effect',
                   'crash_retry_after_restart_refused'),
           'native': 20,
           'kinds': ('runtime',
                     'runtime',
                     'runtime',
                     'approval',
                     'approval',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'control',
                     'runtime',
                     'runtime',
                     'control',
                     'approval',
                     'runtime',
                     'control',
                     'runtime',
                     'probe',
                     'control',
                     'runtime',
                     'runtime',
                     'runtime',
                     'probe',
                     'runtime')},
 '3.0.0': {'ids': ('read_allowed',
                   'policy_refused',
                   'approval_required',
                   'agent_self_approval_refused',
                   'scripted_operator_approval',
                   'changed_payload_refused',
                   'approved_action_allowed',
                   'duplicate_retry_refused',
                   'uncertain_effect_preserved',
                   'uncertain_retry_refused',
                   'budget_first_allowed',
                   'budget_exhausted_refused',
                   'cross_tenant_task_refused',
                   'cancellation_baseline_allowed',
                   'scripted_task_cancellation',
                   'cancelled_task_refused',
                   'expiry_approval_required',
                   'scripted_approval_expiry',
                   'expired_operator_approval_refused',
                   'expired_approval_cannot_authorize',
                   'scripted_deadline_expiry',
                   'expired_task_refused',
                   'concurrent_duplicate_refused',
                   'scripted_process_restart',
                   'duplicate_after_restart_refused',
                   'uncertain_after_restart_refused',
                   'budget_after_restart_refused',
                   'crash_after_simulated_effect',
                   'crash_retry_after_restart_refused',
                   'scripted_journal_record_failure',
                   'journal_record_failure_refused',
                   'scripted_journal_record_recovery',
                   'journal_record_retry_after_recovery',
                   'scripted_journal_saturation_failure',
                   'journal_saturation_failure_refused',
                   'scripted_journal_saturation_recovery',
                   'journal_saturation_retry_after_recovery',
                   'scripted_journal_commit_failure',
                   'journal_commit_failure_refused',
                   'scripted_journal_commit_recovery',
                   'journal_commit_retry_after_recovery'),
           'kinds': ('runtime',
                     'runtime',
                     'runtime',
                     'approval',
                     'approval',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'runtime',
                     'control',
                     'runtime',
                     'runtime',
                     'control',
                     'approval',
                     'runtime',
                     'control',
                     'runtime',
                     'probe',
                     'control',
                     'runtime',
                     'runtime',
                     'runtime',
                     'probe',
                     'runtime',
                     'control',
                     'runtime',
                     'control',
                     'runtime',
                     'control',
                     'runtime',
                     'control',
                     'runtime',
                     'control',
                     'runtime',
                     'control',
                     'runtime'),
           'native': 26}}

JOURNAL_EXPECTATIONS = {'journal_record_failure_refused': {'status': 'refused',
                                    'provider_delta': 0,
                                    'brokered_delta': 1,
                                    'journal_fault': 'record_error',
                                    'journal_failures_delta': 1,
                                    'journal_record_delta': 0,
                                    'grant_absent': True,
                                    'http_status': 503},
 'journal_record_retry_after_recovery': {'status': 'allowed',
                                         'provider_delta': 1,
                                         'brokered_delta': 1,
                                         'journal_fault': '',
                                         'journal_failures_delta': 0,
                                         'journal_record_delta': 1},
 'journal_saturation_failure_refused': {'status': 'refused',
                                        'provider_delta': 0,
                                        'brokered_delta': 1,
                                        'journal_fault': 'saturated',
                                        'journal_failures_delta': 1,
                                        'journal_record_delta': 0,
                                        'grant_absent': True,
                                        'http_status': 503},
 'journal_saturation_retry_after_recovery': {'status': 'allowed',
                                             'provider_delta': 1,
                                             'brokered_delta': 1,
                                             'journal_fault': '',
                                             'journal_failures_delta': 0,
                                             'journal_record_delta': 1},
 'journal_commit_failure_refused': {'status': 'refused',
                                    'provider_delta': 0,
                                    'brokered_delta': 1,
                                    'journal_fault': 'after_commit_error',
                                    'journal_failures_delta': 1,
                                    'journal_record_delta': 1,
                                    'grant_absent': True,
                                    'http_status': 503},
 'journal_commit_retry_after_recovery': {'status': 'allowed',
                                         'provider_delta': 1,
                                         'brokered_delta': 1,
                                         'journal_fault': '',
                                         'journal_failures_delta': 0,
                                         'journal_record_delta': 0}}

SOURCE_ROOTS = (
    "internal/hash/",
    "internal/types/",
    "internal/verifier/",
    "internal/evaluation/",
    "cmd/aaesverify/",
    "schemas/",
)
SOURCE_FILES = (
    "go.mod",
    "LICENSE",
    "README.md",
    "RELEASE-CANDIDATE.md",
    "SPEC.md",
    "SPEC-V3.md",
    "EVALUATION-DISCLOSURE.md",
    "RECORDS.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "tools/external_verify.py",
    "tools/test_external_verify.py",
    "tools/check_cli.py",
)

README = """# External offline evaluation package

This package discloses synthetic LangGraph, CrewAI and Microsoft AutoGen AgentChat
evaluation evidence. It contains the original signed evaluation manifests and a
fixed subset of their artifacts, plus the Apache-2.0 v3 verifier candidate and its
source. Proprietary AAES platform source and producer binaries are omitted.

Read COMPARISON.md for the recorded outcomes and VERIFY.md for commands and trust
limits. `disclosure.json` in each evaluation lists every included and omitted
artifact. The original manifests and signatures are unchanged. Omissions are
explicit; they are never treated as verified files.

This is a locally built candidate distribution, not a new published aaesverify
release. Only the included host binary has been executed here. The public source
has no third-party Go dependencies and can be built offline with Go 1.27 and an
installed toolchain. Verification needs no framework packages or credentials.

The Apache-2.0 LICENSE applies to the verifier and verification tooling. Evidence
files are supplied for inspection. This package grants no rights to omitted AAES
platform source. No private evaluation signing key or repository Git history is
included. Public verifier tests contain disposable synthetic test keys.

Assembly and verification contact no provider and send no email. The source
evaluation was run earlier; this package does not rerun the frameworks.
"""

VERIFY = """# Verify the external package offline

Obtain the package ZIP or PACKAGE.json SHA-256 through a channel you trust. Compare
the archive digest before extracting and running code. An adjacent checksum file
detects changed bytes but does not independently authenticate a publisher.

```sh
shasum -a 256 external-evaluation-package.zip
python3 -S verify.py
```

You can pin a trusted package index:

```sh
python3 -S verify.py --expected-manifest-sha256 YOUR_TRUSTED_PACKAGE_JSON_SHA256
```

The command checks the exact package inventory, its hashes and source allowlist,
then uses the included aaesverify candidate to authenticate each original
evaluation manifest, every disclosed artifact hash and the v3 export's signed
head, chain and Merkle root. It re-seals each current record/2 intent, decision and
record, checks evaluator-input commitments, and binds records and receipt grant
projections to the export. It checks that the manifest and configuration carry the same versioned simulator
label, then regenerates the comparison from those inputs.
It is read-only and imports only Python's standard library. Python socket audit
events are blocked in this Python process only; that hook does not confine the
executed Go verifier. For an OS network boundary covering both on macOS, run the
command under:

```sh
sandbox-exec -p '(version 1) (allow default) (deny network*)' python3 -S verify.py
```

If your archive extractor dropped executable permissions, use
`chmod +x bin/aaesverify` first. For another platform, build the disclosed source:

```sh
cd verifier-source
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOTELEMETRY=off CGO_ENABLED=0 go test ./...
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOTELEMETRY=off CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /tmp/aaesverify-local ./cmd/aaesverify
cd ..
python3 -S verify.py --verifier /tmp/aaesverify-local
```

Build the override outside the package directory to keep its inventory unchanged.
Unlisted files cause verification to fail. Missing Go/toolchain files cause
failure without a download. Only the
included host target is qualified by this package.

To authenticate a known signer, obtain each evaluation key separately and use:

```sh
bin/aaesverify --evaluation evaluations/langgraph --pubkey /trusted/langgraph.pub --json
```

Repeat for CrewAI and AutoGen with their separate keys. Using the supplied
`evidence/ledger.pub` proves internal consistency. These local histories have no
independent witness or TSA; `--require-independent` must fail for them. A successful
export check reports CONSISTENT, with recorded test outcomes shown separately.

## Verification boundary

Disclosed results and sidecar bytes are authenticated by hashes in the original
signed evaluation manifest. The candidate re-seals current record/2 records and
checks their one-to-one binding to export entries, including receipt grant and
identity projections. It sets `sealed_records_resealed` and
`sealed_sidecar_binding_verified` to true after those checks pass.
`full_private_bundle_verified` remains false because source and producer binaries
are omitted. `receipt_chain_verified` is false: this profile does not reconstruct
the receipt chain or establish receipt outcomes independently of the manifest.
See verifier-source/RECORDS.md for exact preimages, supported fields and refusals.

To check the export/sidecar relationship directly, without an outer manifest:

```sh
bin/aaesverify --export evaluations/langgraph/evidence/export.jsonl --records evaluations/langgraph/evidence/records.jsonl --pubkey evaluations/langgraph/evidence/ledger.pub --json
```

This direct check does not authenticate other receipt fields, results or reports.
Use the full package command to authenticate every disclosed artifact.

Source and helper hashes remain signed commitments in the original manifests.
The omitted source and producer binaries cannot be inspected, rebuilt or checked
against those hashes here. Matching commitments across runs are reported as
matching commitments, not as new execution or source verification.

The package index and generated reports are checksummed without a new outer
signature. Hashes, signatures and consistency checks do not establish unseen-call
completeness, real provider execution, human review, independent reproduction,
model quality, production readiness or certification.
"""


def deny_network(event, _args):
    if event.startswith("socket."):
        raise RuntimeError("external verification blocked network: " + event)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def json_text(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def safe_path(name):
    if (
        not isinstance(name, str)
        or not name
        or PurePosixPath(name).is_absolute()
        or any(p in ("", ".", "..") for p in name.split("/"))
        or any(ord(c) < 32 for c in name)
        or "\\" in name
        or ":" in name
    ):
        raise ValueError("unsafe package path: " + repr(name))
    return name


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("package root must be a regular directory")
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError("symlink or special file in package")
        if stat.S_ISREG(mode):
            result[safe_path(path.relative_to(root).as_posix())] = digest(path)
    return result


def source_allowed(name):
    return name in SOURCE_FILES or name.startswith(SOURCE_ROOTS)


def permitted_files(source_names):
    if not {"go.mod", "LICENSE"} <= set(source_names) or not all(
        any(name.startswith(prefix) for name in source_names) for prefix in SOURCE_ROOTS
    ):
        raise ValueError("verifier source inventory is too incomplete to rebuild")
    expected = {
        "README.md",
        "RELEASE-CANDIDATE.md",
        "VERIFY.md",
        "COMPARISON.md",
        "comparison.json",
        "verify.py",
        "LICENSE",
        "bin/aaesverify",
        "build-info.txt",
        "qualification.json",
        "VERIFIER-SOURCE.json",
    }
    for name in source_names:
        safe_path(name)
        if not source_allowed(name):
            raise ValueError("unapproved verifier source path: " + name)
        expected.add("verifier-source/" + name)
    for framework in FRAMEWORKS:
        expected.update(
            "evaluations/" + framework + "/" + name
            for name in (
                *DATA_FILES,
                "evaluation.json",
                "evaluation.sig",
                "disclosure.json",
            )
        )
    return expected


def check_journal_observations(plan, results, transcript):
    """Check signed observations against the suite's fixed refusal/recovery profile."""
    requests = [row for row in transcript if row["path"] == "/v1/brokered"]
    offset = 0
    for case, result in zip(plan["cases"], results, strict=True):
        count = case["brokered_delta"]
        calls = requests[offset:offset + count]
        offset += count
        expected = JOURNAL_EXPECTATIONS.get(case["id"])
        if expected is None:
            continue
        if any(case.get(k) != v for k, v in expected.items()):
            raise ValueError("journal case profile was weakened or changed")
        observation = result.get("journal_observation", {})
        before, after = observation.get("before", {}), observation.get("after", {})
        if before.get("mode") != expected["journal_fault"] or after.get("mode") != expected["journal_fault"] or after.get("failures", -1) - before.get("failures", -1) != expected["journal_failures_delta"]:
            raise ValueError("journal fault activation/counter observation mismatch")
        if observation.get("record_delta") != expected["journal_record_delta"] or len(result.get("record_hashes", [])) != expected["journal_record_delta"]:
            raise ValueError("journal durable record observation mismatch")
        if len(calls) != 1:
            raise ValueError("journal transcript request missing")
        call = calls[0]
        body = call["response"]
        if call["request"].get("effect_key_step") != "tool:" + case["tool"] + ":" + case["call_id"] or call["request"].get("payload") != case["arguments"]:
            raise ValueError("journal call-ID/payload binding mismatch")
        if expected.get("grant_absent"):
            if call["status"] != 503 or body.get("allowed") is not False or (body.get("grant") or {}).get("grant_id") or (body.get("outcome") or {}).get("executed"):
                raise ValueError("journal failure returned a grant, dispatch or non-refusal")
        elif call["status"] != 200 or body.get("allowed") is not True or not (body.get("outcome") or {}).get("executed") or not (body.get("outcome") or {}).get("rail_confirmed"):
            raise ValueError("journal recovery did not record a confirmed execution")
    if offset != len(requests):
        raise ValueError("unaccounted journal transcript requests")


def private_binary(source, expected_sha256, directory):
    """Copy the bundled binary once and execute only that hash-checked copy."""
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("bundled verifier changed after inventory")
    target = directory / "aaesverify"
    target.write_bytes(raw)
    target.chmod(0o500)
    return target


def summarize(root, verifier):
    rows, checks = {}, {}
    for framework in FRAMEWORKS:
        directory = root / "evaluations" / framework
        done = subprocess.run(
            [str(verifier), "--evaluation", str(directory), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": os.defpath, "LANG": "C", "TZ": "UTC"},
        )
        if done.returncode:
            raise ValueError(
                "candidate rejected "
                + framework
                + ": "
                + done.stdout.strip()
                + done.stderr.strip()
            )
        check = json.loads(done.stdout)
        if (
            not all(
                check.get(k) is True
                for k in (
                    "ok",
                    "manifest_signature_ok",
                    "disclosed_artifact_hashes_ok",
                    "sealed_sidecar_bytes_authenticated",
                    "sealed_sidecar_binding_verified",
                    "sealed_records_resealed",
                )
            )
            or check.get("receipt_chain_verified") is not False
            or type(check.get("resealed_record_count")) is not int
            or check["resealed_record_count"] != check.get("export", {}).get("entry_count")
            or check.get("full_private_bundle_verified") is not False
        ):
            raise ValueError("unexpected candidate verification scope")
        checks[framework] = check
        manifest = read_json(directory / "evaluation.json")
        plan = read_json(directory / "cases.json")
        results = read_json(directory / "results.json")
        cases = results["cases"]
        ids = [c["id"] for c in cases]
        profile = SHARED_PROFILES.get(plan.get("suite_version"))
        if (
            manifest["framework"]["name"] != framework
            or manifest["case_suite"] != "aaes.shared-framework-cases/1"
            or plan["schema"] != manifest["case_suite"]
            or plan["suite_version"] != manifest["suite_version"]
            or profile is None
            or tuple(ids) != profile["ids"]
            or tuple(c["kind"] for c in plan["cases"]) != profile["kinds"]
            or manifest["case_count"] != len(profile["ids"])
            or len(set(ids)) != len(profile["ids"])
            or ids != [c["id"] for c in plan["cases"]]
            or [c["kind"] for c in cases] != [c["kind"] for c in plan["cases"]]
            or manifest["case_plan_sha256"] != digest(directory / "cases.json")
        ):
            raise ValueError("shared case coverage/commitment mismatch: " + framework)
        if any(
            type(c.get("passed")) is not bool or c["passed"] != (not c.get("errors"))
            for c in cases
        ):
            raise ValueError("inconsistent recorded assertions: " + framework)
        passed = all(c["passed"] for c in cases)
        if results.get("passed") is not passed or manifest["status"] != (
            "passed" if passed else "failed"
        ):
            raise ValueError("inconsistent recorded aggregate: " + framework)
        config = read_json(directory / "configuration.json")
        provider = manifest.get("provider")
        if not isinstance(provider, str) or re.fullmatch(r"aaes\.local-provider/[1-9][0-9]*", provider) is None or provider != config.get("provider"):
            raise ValueError("simulator provider metadata mismatch: " + framework)
        calls = read_json(directory / "provider-calls.json")
        if any(type(c.get("confirmed")) is not bool for c in calls):
            raise ValueError("missing simulator confirmation status")
        native = (
            sum(c.get("execution_kind") == "graph" for c in cases)
            if framework == "langgraph"
            else sum(
                len(
                    c.get("observed", {}).get(
                        "kickoffs" if framework == "crewai" else "runs", []
                    )
                )
                for c in cases
            )
        )
        if native != profile["native"]:
            raise ValueError("shared suite native execution count mismatch")
        if plan["suite_version"] in ("2.0.0", "3.0.0"):
            for case, result in zip(plan["cases"], cases, strict=True):
                status = ("granted" if case.get("granted") else "refused") if case["kind"] == "approval" else case["status"]
                if result.get("provider_delta") != case["provider_delta"] or result.get("brokered_delta") != case["brokered_delta"] or result.get("shared_status") != status:
                    raise ValueError("expanded shared result differs from expected control/provider outcome")
            if len(calls) != sum(c["provider_delta"] for c in plan["cases"]):
                raise ValueError("expanded shared provider inventory mismatch")
        if plan["suite_version"] == "3.0.0":
            check_journal_observations(plan, cases, read_json(directory / "http-transcript.json"))
        provenance = manifest["provenance"]
        rows[framework] = {
            "framework_version": manifest["framework"]["version"],
            "suite_version": manifest["suite_version"],
            "checks": len(cases),
            "recorded_passed": sum(c["passed"] for c in cases),
            "native_executions": native,
            "simulated_calls": len(calls),
            "simulator_confirmed": sum(c["confirmed"] for c in calls),
            "export_entries": check["export"]["entry_count"],
            "resealed_records": check["resealed_record_count"],
            "export_verdict": check["export"]["verdict"],
            "case_results": {c["id"]: c["passed"] for c in cases},
            "created_at": manifest["created_at"],
            "source_snapshot_commitment": provenance["source_snapshot_sha256"],
            "producer_binary_commitment": manifest["files"]["bin/local-evaluation"],
            "case_plan_sha256": digest(directory / "cases.json"),
            "provider": provider,
            "provider_metadata_consistent": True,
            "policy_hash": read_json(directory / "configuration.json")[
                "policy_bundle_hash"
            ],
            "python": provenance["python"],
            "platform": provenance["platform"],
            "original_manifest_sha256": digest(directory / "evaluation.json"),
            "omitted_artifact_count": len(check["omitted_artifacts"]),
            "independent_attestation": check["independent_attestation"],
        }
    for field in (
        "source_snapshot_commitment",
        "producer_binary_commitment",
        "case_plan_sha256",
        "provider",
        "policy_hash",
        "python",
        "platform",
    ):
        if (
            len({row[field] for row in rows.values()}) != 1
            or not rows[FRAMEWORKS[0]][field]
        ):
            raise ValueError("shared comparison mismatch: " + field)
    if any(
        set(row["case_results"]) != set(rows[FRAMEWORKS[0]]["case_results"])
        for row in rows.values()
    ):
        raise ValueError("shared case IDs differ")
    return {
        "schema": "aaes.external-evaluation-comparison/1",
        "frameworks": rows,
        "total_checks": sum(r["checks"] for r in rows.values()),
        "recorded_passed": sum(r["recorded_passed"] for r in rows.values()),
        "verified_export_entries": sum(r["export_entries"] for r in rows.values()),
        "case_plan_bytes_match": True,
        "source_commitments_match": True,
        "producer_commitments_match": True,
        "source_contents_verified": False,
        "sealed_sidecar_binding_verified": True,
        "sealed_records_resealed": True,
        "resealed_record_count": sum(r["resealed_records"] for r in rows.values()),
        "receipt_chain_verified": False,
        "full_private_bundle_verified": False,
    }, checks


def report(data):
    lines = [
        "# External evaluation comparison",
        "",
        f"The signed result files record {data['recorded_passed']}/{data['total_checks']} passing shared checks. The v3 candidate verifies {data['verified_export_entries']} export entries across three separate histories.",
        "",
        "| Framework | Version | Recorded checks passed | Native executions | Simulated calls | Simulator confirmed | Verified export entries | Export verdict |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for framework in FRAMEWORKS:
        r = data["frameworks"][framework]
        lines.append(
            f"| {framework} | {r['framework_version']} | {r['recorded_passed']}/{r['checks']} | {r['native_executions']} | {r['simulated_calls']} | {r['simulator_confirmed']} | {r['export_entries']} | {r['export_verdict']} |"
        )
    lines += [
        "",
        ("Suite 3.0.0 records twenty-six native executions, three scripted approvals, ten fixture controls and two Go fault probes per framework. Journal cases inject pre-append, saturation and post-durable-append errors at the Record API, check refusal with no grant or dispatch, then retry the same intent after recovery. These are scripted boundary errors; physical disk/fsync faults, database failover, receipt-write failures and existing grant revocation are outside the suite. " if data["frameworks"]["langgraph"]["suite_version"] == "3.0.0" else "Suite 2.0.0 records twenty native framework executions, three scripted approvals, four fixture controls and two fault-injection probes per framework. It covers budgets, expiry, cancellation, cross-tenant tasks, duplicate races and process restart/crash recovery. The race and crash are scripted Go-fixture probes, not native framework parallel execution. " if data["frameworks"]["langgraph"]["suite_version"] == "2.0.0" else "Each run records eight native framework executions and two scripted approval checks. ") + "Provider effects are synthetic; simulator confirmation does not establish external execution. Uncertainty remains explicit in the supplied results.",
        "",
        "Simulator version: `" + data["frameworks"]["langgraph"]["provider"] + "`. Each manifest label agrees with its authenticated configuration, and all three labels match.",
        "",
        "| Shared case | LangGraph | CrewAI | AutoGen AgentChat |",
        "| --- | --- | --- | --- |",
    ]
    for case_id in sorted(data["frameworks"]["langgraph"]["case_results"]):
        lines.append(
            "| `"
            + case_id
            + "` | "
            + " | ".join(
                "PASS" if data["frameworks"][f]["case_results"][case_id] else "FAIL"
                for f in FRAMEWORKS
            )
            + " |"
        )
    r = data["frameworks"]["langgraph"]
    lines += [
        "",
        f"All three original signed manifests record source snapshot commitment `{r['source_snapshot_commitment']}` and producer binary commitment `{r['producer_binary_commitment']}`. The disclosed case-plan bytes match. The source and producer binary are omitted, so these commitments cannot be rechecked against their contents here.",
        "",
        "Every disclosed artifact is checked against its original signed manifest hash. The candidate verifies each v3 export's signed head, chain and Merkle root. The candidate re-seals every current record/2 intent, decision and record, checks evaluator-input commitments, and binds each record and receipt grant projection to its export entry. Receipt-chain seals are outside this profile; all disclosed receipt bytes are authenticated by the original signed manifest.",
        "",
        "The three histories have no independent witness or TSA. Their export verdict is CONSISTENT; the recorded test PASS labels describe assertions in the signed result files. This package does not rerun agents or establish independent reproduction, completeness of unseen calls, model quality, production readiness or certification.",
        "",
        "The proprietary source, source inventories, producer binaries, private build records and private reports are omitted. Each disclosure.json enumerates the exact omissions from the original manifest. Read VERIFY.md for commands, key trust and the verification boundary.",
        "",
    ]
    return "\n".join(lines)


def sums(files):
    return "".join(value + "  " + name + "\n" for name, value in sorted(files.items()))


def verify(root, verifier=None, pin=None):
    if root.is_symlink():
        raise ValueError("package root is a symlink")
    actual = inventory(root)
    if pin and digest(root / "PACKAGE.json") != pin.lower():
        raise ValueError("trusted package index SHA-256 mismatch")
    manifest = read_json(root / "PACKAGE.json")
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported external package schema")
    source = read_json(root / "VERIFIER-SOURCE.json")
    source_files = source["files"]
    expected = manifest["files"]
    source_hash = hashlib.sha256(json_text(source_files).encode()).hexdigest()
    if (
        source.get("schema") != "aaes.public-verifier-source/1"
        or source.get("module") != "github.com/aaes-ai/aaesverify"
        or source.get("inventory_sha256") != source_hash
        or manifest.get("verifier_source_inventory_sha256") != source_hash
    ):
        raise ValueError("public verifier source commitment mismatch")
    if set(expected) != permitted_files(source_files) or set(actual) != set(
        expected
    ) | {"PACKAGE.json", "SHA256SUMS"}:
        raise ValueError("external file allowlist/inventory mismatch")
    for name, value in expected.items():
        if actual[name] != value:
            raise ValueError("package hash mismatch: " + name)
    for name, value in source_files.items():
        if actual["verifier-source/" + name] != value:
            raise ValueError("verifier source index mismatch")
    if (root / "SHA256SUMS").read_text() != sums(
        {**expected, "PACKAGE.json": digest(root / "PACKAGE.json")}
    ):
        raise ValueError("checksum inventory mismatch")
    if (root / "verify.py").read_bytes() != (
        root / "verifier-source/tools/external_verify.py"
    ).read_bytes():
        raise ValueError("standalone verifier differs from disclosed public source")
    if (root / "LICENSE").read_bytes() != (
        root / "verifier-source/LICENSE"
    ).read_bytes():
        raise ValueError("package license differs from public verifier license")
    if verifier:
        data, checks = summarize(root, verifier)
    else:
        with tempfile.TemporaryDirectory() as private:
            data, checks = summarize(root, private_binary(root / "bin/aaesverify", expected["bin/aaesverify"], Path(private)))
    if read_json(root / "comparison.json") != data or (
        root / "COMPARISON.md"
    ).read_text() != report(data):
        raise ValueError("external comparison differs from authenticated evidence")
    if (root / "README.md").read_text() != README or (
        root / "VERIFY.md"
    ).read_text() != VERIFY:
        raise ValueError("instructions differ from public verification source")
    return {
        "schema": "aaes.external-package-verification/1",
        "ok": True,
        "package_index_sha256": digest(root / "PACKAGE.json"),
        "trusted_index_pinned": pin is not None,
        "recorded_passed": data["recorded_passed"],
        "recorded_checks": data["total_checks"],
        "all_recorded_checks_passed": data["recorded_passed"] == data["total_checks"],
        "verified_export_entries": data["verified_export_entries"],
        "sealed_sidecar_binding_verified": True,
        "sealed_records_resealed": True,
        "resealed_record_count": data["resealed_record_count"],
        "receipt_chain_verified": False,
        "full_private_bundle_verified": False,
        "source_contents_verified": False,
        "evaluations": checks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package", type=Path, default=Path(__file__).absolute().parent
    )
    parser.add_argument("--verifier", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    args = parser.parse_args()
    sys.addaudithook(deny_network)
    try:
        result = verify(
            args.package.absolute(),
            args.verifier.absolute() if args.verifier else None,
            args.expected_manifest_sha256,
        )
        print(json_text(result), end="")
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        print("external package verification failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
