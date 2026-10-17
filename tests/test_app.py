
from pathlib import Path
from risk_analysis import analyze_risks

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

def test_risky_actions_are_flagged():
    df = pd.DataFrame(
        {
            "action": ["DeleteTrail", "ConsoleLogin"],
            "location": ["Unknown", "India"],
        }
    )

    result = analyze_risks(df)

    assert result["Risk Flag"].tolist() == [True, False]
    assert "audit logging" in result.loc[0, "Risk Reason"].lower()


def test_unknown_location_gets_explanation():
    df = pd.DataFrame(
        {
            "action": ["ConsoleLogin"],
            "location": ["Unknown"],
        }
    )

    result = analyze_risks(df)

    assert result.loc[0, "Risk Flag"] == False
    assert "location is unknown" in result.loc[0, "Risk Reason"].lower()
