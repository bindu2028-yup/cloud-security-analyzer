
import pandas as pd


RISKY_ACTIONS = {
    "DeleteTrail": "Audit logging configuration may have been deleted.",
    "AttachAdminPolicy": "Administrative privileges may have been granted.",
    "CreateUser": "A new IAM user was created.",
    "CreateAccessKey": "A new access key was created.",
    "DeleteUser": "An IAM user was deleted.",
}


def analyze_risks(df: pd.DataFrame) -> pd.DataFrame:
    """Flag potentially risky events and explain why they were flagged."""
    result = df.copy()

    result["Risk Flag"] = result["action"].isin(RISKY_ACTIONS)

    result["Risk Reason"] = result["action"].map(RISKY_ACTIONS).fillna("")

    # Add a warning when the event's location is unknown.
    unknown_location = (
        result["location"].astype(str).str.strip().str.lower() == "unknown"
    )

    result.loc[unknown_location, "Risk Reason"] = result.loc[
        unknown_location, "Risk Reason"
    ].apply(
        lambda reason: (
            f"{reason} Location is unknown."
            if reason
            else "Location is unknown; review the event."
        )
    )

    return result
