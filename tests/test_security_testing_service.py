"""Tests for the O3 security testing and analysis module."""

from __future__ import annotations

import io

from app import create_app
from services.security_testing_service import build_security_corpus, run_security_testing_suite


class UploadedFile:
    def __init__(self, name: str, data: bytes) -> None:
        self.filename = name
        self._data = data

    def read(self) -> bytes:
        return self._data


def make_uploaded_files(payloads: list[tuple[str, bytes]]) -> list[UploadedFile]:
    return [UploadedFile(name, data) for name, data in payloads]


def test_security_corpus_has_ten_inputs_and_required_formats():
    corpus = build_security_corpus()

    assert len(corpus) == 10
    names = {sample.name for sample in corpus}
    assert "pdf-mini" in names
    assert "png-mini" in names
    assert "jpg-mini" in names


def test_security_testing_suite_returns_all_major_sections():
    report = run_security_testing_suite(
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


def test_security_testing_suite_accepts_single_uploaded_file():
    report = run_security_testing_suite(
        quick=True,
        files=make_uploaded_files([("single.pdf", b"%PDF-1.7 single file")]),
        benchmark_sizes=(256,),
        benchmark_repeats=1,
    )

    assert len(report["file_round_trip"]) == 1
    assert report["file_round_trip"][0]["status"] == "PASS"


def test_security_testing_suite_accepts_multiple_uploaded_files():
    payloads = [
        ("doc-1.pdf", b"%PDF-1.7 example-1"),
        ("doc-2.png", b"\x89PNG\r\n\x1a\nexample-2"),
        ("doc-3.jpg", b"\xff\xd8\xffexample-3"),
        ("doc-4.txt", b"plain text 4"),
        ("doc-5.csv", b"a,b\n1,2\n"),
        ("doc-6.docx", b"docx-like-6"),
        ("doc-7.json", b'{"file":7}'),
        ("doc-8.md", b"# markdown 8"),
        ("doc-9.zip", b"PK\x03\x04zip-9"),
        ("doc-10.bmp", b"BMbitmap-10"),
    ]

    report = run_security_testing_suite(
        quick=True,
        files=make_uploaded_files(payloads),
        benchmark_sizes=(256,),
        benchmark_repeats=1,
    )

    assert len(report["file_round_trip"]) == 10
    assert all(item["passed"] for item in report["file_round_trip"])
    assert report["round_trip_total"] == 20


def test_security_testing_suite_accepts_three_uploaded_files():
    report = run_security_testing_suite(
        quick=True,
        files=make_uploaded_files([
            ("file-1.pdf", b"%PDF-1.7 file-1"),
            ("file-2.png", b"\x89PNG\r\n\x1a\nfile-2"),
            ("file-3.jpg", b"\xff\xd8\xfffile-3"),
        ]),
        benchmark_sizes=(256,),
        benchmark_repeats=1,
    )

    assert len(report["file_round_trip"]) == 3
    assert report["round_trip_total"] == 6
    assert report["round_trip_success"] == 6


def test_security_testing_suite_accepts_five_uploaded_files():
    report = run_security_testing_suite(
        quick=True,
        files=make_uploaded_files([
            ("file-1.pdf", b"%PDF-1.7 file-1"),
            ("file-2.png", b"\x89PNG\r\n\x1a\nfile-2"),
            ("file-3.jpg", b"\xff\xd8\xfffile-3"),
            ("file-4.txt", b"file-4 text"),
            ("file-5.csv", b"a,b\n5,6\n"),
        ]),
        benchmark_sizes=(256,),
        benchmark_repeats=1,
    )

    assert len(report["file_round_trip"]) == 5
    assert report["round_trip_total"] == 10
    assert report["round_trip_success"] == 10


def test_security_testing_suite_rejects_duplicate_uploaded_files():
    payloads = [
        ("dup-1.pdf", b"same-bytes"),
        ("dup-2.png", b"same-bytes"),
        ("doc-3.jpg", b"unique-3"),
        ("doc-4.txt", b"unique-4"),
        ("doc-5.csv", b"unique-5"),
    ] + [
        (f"doc-{index}.txt", f"unique-{index}".encode("utf-8"))
        for index in range(6, 11)
    ]

    try:
        run_security_testing_suite(
            quick=True,
            files=make_uploaded_files(payloads),
            benchmark_sizes=(256,),
            benchmark_repeats=1,
        )
        assert False, "Expected ValueError for duplicate files"
    except ValueError as exc:
        assert "File duplikat" in str(exc)


def test_security_testing_suite_rejects_empty_uploaded_file_list():
    try:
        run_security_testing_suite(
            quick=True,
            files=[],
            benchmark_sizes=(256,),
            benchmark_repeats=1,
        )
        assert False, "Expected ValueError for empty file list"
    except ValueError as exc:
        assert "Minimal 1 file" in str(exc)


def test_testing_route_returns_json_report():
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        data = {
            "files": [
                (io.BytesIO(b"%PDF-1.7 sample 1"), "sample-1.pdf"),
                (io.BytesIO(b"\x89PNG\r\n\x1a\n sample 2"), "sample-2.png"),
                (io.BytesIO(b"\xff\xd8\xff sample 3"), "sample-3.jpg"),
                (io.BytesIO(b"text sample 4"), "sample-4.txt"),
                (io.BytesIO(b"csv,sample,5"), "sample-5.csv"),
                (io.BytesIO(b"docx sample 6"), "sample-6.docx"),
                (io.BytesIO(b"json sample 7"), "sample-7.json"),
                (io.BytesIO(b"md sample 8"), "sample-8.md"),
                (io.BytesIO(b"zip sample 9"), "sample-9.zip"),
                (io.BytesIO(b"bmp sample 10"), "sample-10.bmp"),
            ],
        }
        response = client.post("/testing/run", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    assert body["data"]["quick_mode"] is True
    assert body["data"]["round_trip_success"] == body["data"]["round_trip_total"]
    assert len(body["data"]["file_round_trip"]) == 10


def test_testing_route_accepts_single_uploaded_file():
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        data = {
            "files": [
                (io.BytesIO(b"%PDF-1.7 single file"), "single.pdf"),
            ],
        }
        response = client.post("/testing/run", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    assert len(body["data"]["file_round_trip"]) == 1


def test_testing_route_accepts_three_uploaded_files():
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        data = {
            "files": [
                (io.BytesIO(b"%PDF-1.7 file-1"), "file-1.pdf"),
                (io.BytesIO(b"\x89PNG\r\n\x1a\nfile-2"), "file-2.png"),
                (io.BytesIO(b"\xff\xd8\xfffile-3"), "file-3.jpg"),
            ],
        }
        response = client.post("/testing/run", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    assert len(body["data"]["file_round_trip"]) == 3
    assert body["data"]["round_trip_total"] == 6
    assert body["data"]["round_trip_success"] == 6


def test_testing_route_rejects_duplicate_files():
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        data = {
            "files": [
                (io.BytesIO(b"same-bytes"), "sample-1.txt"),
                (io.BytesIO(b"same-bytes"), "sample-2.txt"),
                (io.BytesIO(b"unique-3"), "sample-3.txt"),
                (io.BytesIO(b"unique-4"), "sample-4.txt"),
                (io.BytesIO(b"unique-5"), "sample-5.txt"),
                (io.BytesIO(b"unique-6"), "sample-6.txt"),
                (io.BytesIO(b"unique-7"), "sample-7.txt"),
                (io.BytesIO(b"unique-8"), "sample-8.txt"),
                (io.BytesIO(b"unique-9"), "sample-9.txt"),
                (io.BytesIO(b"unique-10"), "sample-10.txt"),
            ],
        }
        response = client.post("/testing/run", data=data, content_type="multipart/form-data")

    assert response.status_code == 400
    body = response.get_json()
    assert body["success"] is False
    assert "File duplikat" in body["error"]