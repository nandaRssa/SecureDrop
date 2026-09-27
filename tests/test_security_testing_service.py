"""Tests for the O3 security testing and analysis module."""

from __future__ import annotations

from app import create_app
from services.security_testing_service import build_security_corpus, run_security_testing_suite


def test_security_corpus_has_ten_inputs_and_required_formats():
    corpus = build_security_corpus()

    assert len(corpus) == 10
    names = {sample.name for sample in corpus}
    assert "pdf-mini" in names
    assert "png-mini" in names
    assert "jpg-mini" in names


def test_security_testing_suite_returns_all_major_sections():
    report = run_security_testing_suite(
        password="security-testing-password",
        quick=True,
        benchmark_sizes=(256,),
        benchmark_repeats=1,
    )

    assert report["round_trip_total"] == 20
    assert report["round_trip_success"] == 20
    assert len(report["benchmark"]) == 2
    assert len(report["comparison"]) == 1
    assert len(report["avalanche"]) == 4
    assert len(report["entropy"]["results"]) == 2
    assert len(report["integrity"]) == 3
    assert all(item["passed"] for item in report["integrity"])


def test_testing_route_returns_json_report():
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post("/testing/run", data={"password": "route-testing-password"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    assert body["data"]["quick_mode"] is True
    assert body["data"]["round_trip_success"] == body["data"]["round_trip_total"]