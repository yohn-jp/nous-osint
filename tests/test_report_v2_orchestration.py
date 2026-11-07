"""Call budget and repair immutability tests for the integrated editor."""
from copy import deepcopy

import pytest

from nous.report_pipeline import ReportError, run_editorial_pipeline
from test_report_pipeline import FixtureRunner, evidence_bundle


class RepairRunner(FixtureRunner):
    def run(self, stage, payload, **kwargs):
        value = super().run(stage, payload, **kwargs)
        if stage == "claim_review":
            value["reviews"][0].update(decision="needs_revision", reason_code="unclear")
        return value


def test_bounded_repair_runs_exactly_four_calls():
    runner = RepairRunner()
    article, _ = run_editorial_pipeline(
        evidence_bundle(), template_id="security-daily", run_id="repair",
        runner=runner, persist_stage=lambda *_: None,
    )
    assert runner.calls == ["claims", "claim_review", "claim_repair", "claim_rereview"]
    assert article["schema_version"] == 2


def test_repair_cannot_introduce_another_claim():
    class InvalidRepair(RepairRunner):
        def run(self, stage, payload, **kwargs):
            value = super().run(stage, payload, **kwargs)
            if stage == "claim_repair":
                extra = deepcopy(value["claims"][0])
                extra["claim_id"] = "C002"
                value["claims"].append(extra)
            return value
    with pytest.raises(ReportError):
        run_editorial_pipeline(evidence_bundle(), template_id="security-daily",
                               run_id="invalid-repair", runner=InvalidRepair(),
                               persist_stage=lambda *_: None)
