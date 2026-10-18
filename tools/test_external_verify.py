# SPDX-License-Identifier: Apache-2.0
"""Public wrapper checks; native signature/export tests live in the Go module."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import external_verify as reader

IDS = (
    "read_allowed",
    "policy_refused",
    "approval_required",
    "agent_self_approval_refused",
    "scripted_operator_approval",
    "changed_payload_refused",
    "approved_action_allowed",
    "duplicate_retry_refused",
    "uncertain_effect_preserved",
    "uncertain_retry_refused",
)


class ExternalReaderTests(unittest.TestCase):
    def fixtures(self, root, version="1.0.0"):
        # Test result metadata only. The mocked native result is never evidence
        # of execution; real signatures and v3 chains are tested in Go.
        for framework in reader.FRAMEWORKS:
            path = root / "evaluations" / framework
            path.mkdir(parents=True)
            plan, results = [], []
            profile = reader.SHARED_PROFILES[version]
            for index, (case_id, kind) in enumerate(zip(profile["ids"], profile["kinds"], strict=True)):
                plan.append({"id": case_id, "kind": kind, "status":"allowed" if kind=="runtime" else "completed", "provider_delta":1 if index in (0,1,2) else 0, "brokered_delta":1 if kind=="runtime" else 0, "granted":True})
                if version == "3.0.0" and case_id in reader.JOURNAL_EXPECTATIONS:
                    plan[-1].update(reader.JOURNAL_EXPECTATIONS[case_id])
                    plan[-1].update(tool="internal_state", call_id=case_id, arguments={"object_id": "synthetic"})
                results.append(
                    {
                        "id": case_id,
                        "kind": kind,
                        "passed": True,
                        "errors": [],
                        "execution_kind": "graph" if kind == "runtime" else "approval",
                        "provider_delta":plan[-1]["provider_delta"],
                        "brokered_delta":plan[-1]["brokered_delta"],
                        "shared_status":"granted" if kind=="approval" else plan[-1]["status"],
                        "observed": {"kickoffs": [{}], "runs": [{}]}
                        if kind == "runtime"
                        else {},
                    }
                )
            transcript = []
            for case, result in zip(plan, results, strict=True):
                if version == "3.0.0" and case["id"] in reader.JOURNAL_EXPECTATIONS:
                    result["journal_observation"] = {"before": {"mode":case["journal_fault"], "failures":0}, "after": {"mode":case["journal_fault"], "failures":case["journal_failures_delta"]}, "record_delta":case["journal_record_delta"]}
                    result["record_hashes"] = ["f" * 64] * case["journal_record_delta"]
                for _ in range(case["brokered_delta"]):
                    allowed = case["status"] == "allowed"
                    transcript.append({"path":"/v1/brokered", "status":503 if case.get("grant_absent") else 200, "request":{"effect_key_step":"tool:"+case.get("tool", "read")+":"+case.get("call_id", case["id"]), "payload":case.get("arguments", {})}, "response":{"allowed":allowed, "outcome":{"executed":allowed, "rail_confirmed":allowed}}})
            (path / "http-transcript.json").write_text(reader.json_text(transcript))
            (path / "cases.json").write_text(
                reader.json_text(
                    {
                        "schema": "aaes.shared-framework-cases/1",
                        "suite_version": version,
                        "cases": plan,
                    }
                )
            )
            manifest = {
                "schema": "aaes.framework-evaluation/1",
                "framework": {"name": framework, "version": "synthetic-test"},
                "case_suite": "aaes.shared-framework-cases/1",
                "suite_version": version,
                "case_count": len(profile["ids"]),
                "case_plan_sha256": reader.digest(path / "cases.json"),
                "status": "passed",
                "created_at": "2026-01-01T00:00:00Z",
                "provenance": {
                    "source_snapshot_sha256": "a" * 64,
                    "python": "test",
                    "platform": "test",
                },
                "provider": "aaes.local-provider/1",
                "files": {"bin/local-evaluation": "b" * 64},
            }
            (path / "evaluation.json").write_text(reader.json_text(manifest))
            (path / "results.json").write_text(
                reader.json_text({"passed": True, "cases": results})
            )
            (path / "provider-calls.json").write_text(
                reader.json_text(
                    [{"confirmed": True}] * sum(c["provider_delta"] for c in plan) if version == "3.0.0" else [{"confirmed": True}, {"confirmed": True}, {"confirmed": False}]
                )
            )
            (path / "configuration.json").write_text(
                reader.json_text({"policy_bundle_hash": "c" * 64, "provider": "aaes.local-provider/1"})
            )
        return {
            "ok": True,
            "manifest_signature_ok": True,
            "disclosed_artifact_hashes_ok": True,
            "sealed_sidecar_bytes_authenticated": True,
            "sealed_sidecar_binding_verified": True,
            "sealed_records_resealed": True,
            "resealed_record_count": 9,
            "receipt_chain_verified": False,
            "full_private_bundle_verified": False,
            "omitted_artifacts": ["sources/omitted.go"],
            "independent_attestation": False,
            "export": {"entry_count": 9, "verdict": "CONSISTENT"},
        }

    def test_journal_suite_and_semantic_mutations(self):
        for mutation in (None, "disable_fault", "hide_fault", "wrong_records", "return_grant", "dispatch", "missing_request", "different_payload"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                check = self.fixtures(root, "3.0.0")
                directory = root / "evaluations/langgraph"
                plan = reader.read_json(directory / "cases.json")
                result = reader.read_json(directory / "results.json")
                transcript = reader.read_json(directory / "http-transcript.json")
                n = next(i for i,c in enumerate(plan["cases"]) if c["id"] == "journal_record_failure_refused")
                offset = sum(c["brokered_delta"] for c in plan["cases"][:n])
                if mutation == "disable_fault": plan["cases"][n]["journal_fault"] = ""
                elif mutation == "hide_fault": result["cases"][n]["journal_observation"]["after"]["failures"] = 0
                elif mutation == "wrong_records": result["cases"][n]["record_hashes"] = ["f"*64]
                elif mutation == "return_grant": transcript[offset]["response"]["grant"] = {"grant_id":"forged"}
                elif mutation == "dispatch": transcript[offset]["response"]["outcome"]["executed"] = True
                elif mutation == "missing_request": transcript.pop(offset)
                elif mutation == "different_payload": transcript[offset]["request"]["payload"] = {"object_id":"other"}
                (directory / "cases.json").write_text(reader.json_text(plan))
                manifest = reader.read_json(directory / "evaluation.json")
                manifest["case_plan_sha256"] = reader.digest(directory / "cases.json")
                (directory / "evaluation.json").write_text(reader.json_text(manifest))
                (directory / "results.json").write_text(reader.json_text(result))
                (directory / "http-transcript.json").write_text(reader.json_text(transcript))
                with patch("external_verify.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(check), "")):
                    if mutation is None:
                        data, _ = reader.summarize(root, Path("/test/verifier"))
                        self.assertEqual(data["recorded_passed"], 123)
                        self.assertTrue(all(row["native_executions"] == 26 for row in data["frameworks"].values()))
                    else:
                        with self.assertRaises(ValueError): reader.summarize(root, Path("/test/verifier"))

    def test_expanded_profile_and_counter_mutations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            check = self.fixtures(root, "2.0.0")
            native = subprocess.CompletedProcess([], 0, json.dumps(check), "")
            with patch("external_verify.subprocess.run", return_value=native):
                data, _ = reader.summarize(root, Path("/test/verifier"))
                self.assertEqual(data["recorded_passed"], 87)
                self.assertTrue(all(row["native_executions"] == 20 for row in data["frameworks"].values()))
                self.assertIn("two fault-injection probes", reader.report(data))
                path = root / "evaluations/autogen/results.json"
                result = reader.read_json(path)
                result["cases"][0]["provider_delta"] = 99
                path.write_text(reader.json_text(result))
                with self.assertRaisesRegex(ValueError, "expanded shared result"):
                    reader.summarize(root, Path("/test/verifier"))

    def test_provider_metadata_rejected_even_when_native_checks_report_success(self):
        for value in (None, "aaes.local-provider/2", "other/1", "aaes.local-provider/01"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                check = self.fixtures(root)
                path = root / "evaluations/langgraph/configuration.json"
                config = reader.read_json(path)
                config["provider"] = value
                path.write_text(reader.json_text(config))
                with patch("external_verify.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(check), "")):
                    with self.assertRaisesRegex(ValueError, "provider metadata mismatch"):
                        reader.summarize(root, Path("/test/verifier"))

    def test_source_and_package_allowlists_exclude_proprietary_trees(self):
        for name in (
            "aaes/internal/gateway/main.go",
            "internal/gateway/main.go",
            "internal/journal/seal.go",
            ".git/config",
            "tools/private.py",
        ):
            self.assertFalse(reader.source_allowed(name), name)
        complete = ["go.mod", "LICENSE", "internal/hash/hash.go", "internal/types/money.go", "internal/verifier/verifier.go",
                    "internal/evaluation/disclosure.go", "cmd/aaesverify/main.go", "schemas/export.schema.json"]
        files = reader.permitted_files(complete)
        self.assertFalse(
            any(p.startswith(("shared-source/", "sources/")) for p in files)
        )
        self.assertNotIn("bin/local-evaluation", files)
        for name in ("internal/journal/seal.go", "internal/verifier/../../private.go"):
            with self.assertRaisesRegex(ValueError, "unapproved|unsafe|path"):
                reader.permitted_files([*complete, name])
        with self.assertRaisesRegex(ValueError, "too incomplete"):
            reader.permitted_files([name for name in complete if not name.startswith("internal/verifier/")])

    def test_comparison_preserves_verification_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            check = self.fixtures(root)
            with patch(
                "external_verify.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, json.dumps(check), ""),
            ):
                data, _ = reader.summarize(root, Path("/test/verifier"))
            self.assertEqual(data["recorded_passed"], 30)
            self.assertEqual(data["verified_export_entries"], 27)
            self.assertFalse(data["source_contents_verified"])
            self.assertTrue(data["sealed_sidecar_binding_verified"])
            self.assertEqual(data["resealed_record_count"], 27)
            self.assertFalse(data["receipt_chain_verified"])
            self.assertFalse(data["full_private_bundle_verified"])
            text = reader.report(data)
            self.assertIn("cannot be rechecked against their contents", text)
            self.assertIn("re-seals every current record/2", text)

    def test_broader_candidate_scope_cannot_be_silently_claimed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            check = self.fixtures(root)
            check["full_private_bundle_verified"] = True
            with patch(
                "external_verify.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, json.dumps(check), ""),
            ):
                with self.assertRaisesRegex(
                    ValueError, "unexpected candidate verification scope"
                ):
                    reader.summarize(root, Path("/test/verifier"))

    def test_missing_binding_or_wrong_reseal_count_is_refused(self):
        for field, value in (("manifest_signature_ok", False), ("disclosed_artifact_hashes_ok", False), ("sealed_sidecar_binding_verified", False), ("sealed_records_resealed", False), ("resealed_record_count", 8), ("resealed_record_count", True), ("receipt_chain_verified", True)):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                check = self.fixtures(root)
                check[field] = value
                with patch("external_verify.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(check), "")):
                    with self.assertRaisesRegex(ValueError, "unexpected candidate verification scope"):
                        reader.summarize(root, Path("/test/verifier"))

    def test_changed_shared_input_and_incomplete_results_fail(self):
        for mutation in ("changed_plan", "incomplete_results", "lying_aggregate"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                check = self.fixtures(root)
                path = root / "evaluations/autogen"
                name = "cases.json" if mutation == "changed_plan" else "results.json"
                document = reader.read_json(path / name)
                if mutation == "changed_plan":
                    document["cases"][0]["id"] = "substituted"
                elif mutation == "incomplete_results":
                    document["cases"].pop()
                else:
                    document["passed"] = False
                (path / name).write_text(reader.json_text(document))
                with patch(
                    "external_verify.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, json.dumps(check), ""
                    ),
                ):
                    with self.assertRaises(ValueError):
                        reader.summarize(root, Path("/test/verifier"))

    def test_failed_assertions_remain_failed_after_authentication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            check = self.fixtures(root)
            path = root / "evaluations/autogen"
            results = reader.read_json(path / "results.json")
            results["passed"] = results["cases"][0]["passed"] = False
            results["cases"][0]["errors"] = ["synthetic failing assertion"]
            (path / "results.json").write_text(reader.json_text(results))
            manifest = reader.read_json(path / "evaluation.json")
            manifest["status"] = "failed"
            (path / "evaluation.json").write_text(reader.json_text(manifest))
            with patch(
                "external_verify.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, json.dumps(check), ""),
            ):
                data, _ = reader.summarize(root, Path("/test/verifier"))
            self.assertEqual(data["recorded_passed"], 29)

    def test_duplicate_json_unsafe_paths_and_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "duplicate.json").write_text('{"a":1,"a":2}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON"):
                reader.read_json(root / "duplicate.json")
            for name in ("../escape", "C:/drive", "a\\b", "a\nline", "/absolute"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    reader.safe_path(name)
            (root / "link").symlink_to(root / "duplicate.json")
            with self.assertRaisesRegex(ValueError, "symlink"):
                reader.inventory(root)

    def test_trusted_pin_is_checked_before_executing_a_binary(self):
        with (
            tempfile.TemporaryDirectory() as temp,
            patch("external_verify.subprocess.run") as native,
        ):
            root = Path(temp)
            (root / "PACKAGE.json").write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "trusted package index"):
                reader.verify(root, pin="0" * 64)
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
