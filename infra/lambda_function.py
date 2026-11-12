import json
import os
import urllib.parse
from datetime import datetime, timezone
import boto3

s3 = boto3.client("s3")

CLEAN_BUCKET = os.environ.get("CLEAN_BUCKET", "pii-guard-clean-zone-sg23")
SALT = os.environ.get("PII_SALT", "default_dev_salt")

# Temporary mock until Yashvanth's /agents module is merged
def mock_run_pii_pipeline(raw_csv_text: str, salt: str) -> tuple[str, dict]:
    audit_report = {
        "status": "MOCK_PASS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "Placeholder pipeline active. Waiting for Yashvanth's agent merge."
    }
    return raw_csv_text, audit_report

try:
    from agents.pipeline import run_pii_pipeline
except ImportError:
    run_pii_pipeline = mock_run_pii_pipeline


def lambda_handler(event, context):
    for record in event.get("Records", []):
        raw_bucket = record["s3"]["bucket"]["name"]
        raw_key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        filename = os.path.basename(raw_key)

        if not filename.endswith(".csv"):
            continue

        # 1. Read raw CSV from S3
        response = s3.get_object(Bucket=raw_bucket, Key=raw_key)
        raw_csv_text = response["Body"].read().decode("utf-8")

        # 2. Execute multi-agent PII pipeline
        clean_csv_text, audit_report = run_pii_pipeline(raw_csv_text, SALT)

        # 3. Route clean CSV into dataset-specific folder for clean Athena table schemas
        dataset_folder = "tickets" if "ticket" in filename.lower() else "transactions"
        clean_key = f"{dataset_folder}/{filename}"

        s3.put_object(
            Bucket=CLEAN_BUCKET,
            Key=clean_key,
            Body=clean_csv_text.encode("utf-8"),
            ContentType="text/csv"
        )

        # 4. Save audit report under /logs in the clean bucket
        log_key = f"logs/{filename.replace('.csv', '_audit.json')}"
        s3.put_object(
            Bucket=CLEAN_BUCKET,
            Key=log_key,
            Body=json.dumps(audit_report, indent=2).encode("utf-8"),
            ContentType="application/json"
        )

    return {"statusCode": 200, "body": json.dumps("PII pipeline execution complete.")}