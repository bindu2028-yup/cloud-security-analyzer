
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSV_FILE = PROJECT_ROOT / "security_logs.csv"


def test_security_logs_file_exists():
    assert CSV_FILE.exists()


def test_security_logs_has_required_columns():
    df = pd.read_csv(CSV_FILE)

    required_columns = {
        "timestamp",
        "user",
        "source_ip",
        "action",
        "resource",
        "status",
        "location",
        "admin",
    }

    assert required_columns.issubset(df.columns)


def test_security_logs_is_not_empty():
    df = pd.read_csv(CSV_FILE)

    assert not df.empty
