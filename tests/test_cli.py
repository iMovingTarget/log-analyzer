from pathlib import Path

from log_analyzer.__main__ import main

FIXTURE = Path(__file__).parent / "fixtures" / "auth_sample.log"


def test_end_to_end_writes_all_reports(tmp_path):
    out = tmp_path / "out"
    rc = main(["--file", str(FIXTURE), "--out", str(out), "--no-db"])

    assert rc == 0
    assert {p.name for p in out.iterdir()} == {
        "auth_sample.json",
        "auth_sample.csv",
        "auth_sample.html",
    }


def test_missing_log_file_exits_2(tmp_path, capsys):
    rc = main(["--file", str(tmp_path / "nope.log"), "--no-db"])

    assert rc == 2
    assert "cannot read" in capsys.readouterr().err


def test_missing_allowlist_is_an_error_not_silently_ignored(tmp_path, capsys):
    rc = main(["--file", str(FIXTURE), "--allowlist", str(tmp_path / "typo.txt"), "--no-db"])

    assert rc == 2
    assert "typo.txt" in capsys.readouterr().err


def test_invalid_utf8_does_not_crash(tmp_path):
    log = tmp_path / "hostile.log"
    log.write_bytes(
        b"Failed password for root from 1.2.3.4 port 22\n"
        b"Invalid user \xff\xfe from 9.9.9.9 port 22\n"
    )
    rc = main(["--file", str(log), "--out", str(tmp_path / "out"), "--no-db"])

    assert rc == 0


def test_version_flag(capsys):
    import pytest

    from log_analyzer import __version__

    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_console_output_is_ascii(tmp_path, capsys):
    # Non-ASCII output (it used to print an emoji) crashes on Windows when
    # stdout is redirected to a file with a legacy code page.
    main(["--file", str(FIXTURE), "--out", str(tmp_path), "--no-db"])
    assert capsys.readouterr().out.isascii()


def test_missing_geoip_db_exits_2(tmp_path, capsys):
    rc = main(["--file", str(FIXTURE), "--geoip-db", str(tmp_path / "nope.mmdb"), "--no-db"])

    assert rc == 2
    assert "GeoIP database not found" in capsys.readouterr().err
