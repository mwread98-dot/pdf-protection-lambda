import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote_plus

import boto3
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3 = boto3.client("s3")
secrets_manager = boto3.client("secretsmanager")

OUTPUT_BUCKET = os.environ["OUTPUT_BUCKET"]
OWNER_PASSWORD_SECRET_ARN = os.environ["OWNER_PASSWORD_SECRET_ARN"]

# Cache the password for warm Lambda invocations.
_cached_owner_password = None


class PdfProcessingError(Exception):
    """Raised when a PDF cannot be protected or verified."""


def get_owner_password():
    global _cached_owner_password

    if _cached_owner_password is not None:
        return _cached_owner_password

    response = secrets_manager.get_secret_value(
        SecretId=OWNER_PASSWORD_SECRET_ARN
    )

    secret_string = response.get("SecretString")
    if not secret_string:
        raise PdfProcessingError(
            "The Secrets Manager secret does not contain SecretString."
        )

    try:
        secret = json.loads(secret_string)
        password = secret["owner_password"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PdfProcessingError(
            "The secret must be JSON containing an owner_password field."
        ) from exc

    if not isinstance(password, str) or not password:
        raise PdfProcessingError(
            "The owner_password value must be a non-empty string."
        )

    _cached_owner_password = password
    return password


def run_command(command, description):
    """
    Run a command without logging its argument list.

    This is important because the qpdf command contains the owner password.
    """
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=840,
        check=False,
    )

    if result.returncode not in (0, 3):
        # qpdf exit code 3 means the operation completed with warnings.
        safe_error = result.stderr.strip()

        raise PdfProcessingError(
            f"{description} failed with exit code "
            f"{result.returncode}: {safe_error}"
        )

    if result.returncode == 3:
        logger.warning("%s completed with qpdf warnings.", description)

    return result


def protect_pdf(input_path, output_path, owner_password):
    command = [
        "qpdf",
        "--encrypt",
        "",                  # Empty user password: no password needed to open
        owner_password,      # Owner/permissions password
        "256",               # AES-256
        "--print=low",       # Low-resolution printing only
        "--modify=none",     # Disable all document modification
        "--extract=n",       # Disable general extraction/copying
        "--accessibility=y", # Retain accessibility extraction
        "--",
        str(input_path),
        str(output_path),
    ]

    run_command(command, "PDF protection")


def verify_pdf(output_path):
    # Check that the produced PDF is structurally readable.
    run_command(
        [
            "qpdf",
            "--password=",
            "--check",
            str(output_path),
        ],
        "PDF structural verification",
    )

    encryption_result = run_command(
        [
            "qpdf",
            "--password=",
            "--show-encryption",
            str(output_path),
        ],
        "PDF encryption verification",
    )

    output = encryption_result.stdout.lower()

    required_results = [
        "print low resolution: allowed",
        "print high resolution: not allowed",
        "extract for accessibility: allowed",
        "extract for any purpose: not allowed",
        "modify document assembly: not allowed",
        "modify forms: not allowed",
        "modify annotations: not allowed",
        "modify other: not allowed",
    ]

    missing = [
        result for result in required_results
        if result not in output
    ]

    # AES-256 normally appears as AESv3 for streams, strings and files.
    if "aesv3" not in output:
        missing.append("AESv3 encryption")

    if missing:
        raise PdfProcessingError(
            "Output PDF failed permission verification. Missing: "
            + ", ".join(missing)
        )


def output_key_for(source_key):
    """
    Preserve the input key structure.

    Example:
      incoming/customer-a/report.pdf
    becomes:
      incoming/customer-a/report.pdf
    in the separate output bucket.
    """
    return source_key


def process_record(record, owner_password):
    bucket = record["s3"]["bucket"]["name"]
    key = unquote_plus(record["s3"]["object"]["key"])

    if not key.lower().endswith(".pdf"):
        logger.info("Skipping non-PDF object: s3://%s/%s", bucket, key)
        return {
            "status": "skipped",
            "source": f"s3://{bucket}/{key}",
        }

    version_id = record["s3"]["object"].get("versionId")
    output_key = output_key_for(key)

    logger.info(
        "Processing s3://%s/%s to s3://%s/%s",
        bucket,
        key,
        OUTPUT_BUCKET,
        output_key,
    )

    with tempfile.TemporaryDirectory(dir="/tmp") as work_dir:
        work_path = Path(work_dir)
        input_path = work_path / "input.pdf"
        output_path = work_path / "protected.pdf"

        download_parameters = {
            "Bucket": bucket,
            "Key": key,
        }

        if version_id:
            download_parameters["VersionId"] = version_id

        try:
            s3.download_file(
                bucket,
                key,
                str(input_path),
                ExtraArgs=(
                    {"VersionId": version_id}
                    if version_id
                    else None
                ),
            )
        except ClientError as exc:
            raise PdfProcessingError(
                f"Unable to download s3://{bucket}/{key}"
            ) from exc

        if input_path.stat().st_size == 0:
            raise PdfProcessingError("The input object is empty.")

        protect_pdf(input_path, output_path, owner_password)
        verify_pdf(output_path)

        source_version = version_id or "unversioned"

        try:
            s3.upload_file(
                str(output_path),
                OUTPUT_BUCKET,
                output_key,
                ExtraArgs={
                    "ContentType": "application/pdf",
                    "Metadata": {
                        "source-bucket": bucket,
                        "source-key": key,
                        "source-version": source_version,
                        "pdf-protection": "aes-256-restricted",
                    },
                    "ServerSideEncryption": "AES256",
                },
            )
        except ClientError as exc:
            raise PdfProcessingError(
                f"Unable to upload s3://{OUTPUT_BUCKET}/{output_key}"
            ) from exc

    return {
        "status": "processed",
        "source": f"s3://{bucket}/{key}",
        "destination": f"s3://{OUTPUT_BUCKET}/{output_key}",
    }


def lambda_handler(event, context):
    records = event.get("Records", [])

    if not records:
        logger.warning("Invocation contained no S3 records.")
        return {
            "statusCode": 200,
            "processed": [],
            "message": "No S3 records supplied.",
        }

    owner_password = get_owner_password()
    results = []

    for record in records:
        if record.get("eventSource") != "aws:s3":
            logger.warning("Skipping an event that is not from S3.")
            continue

        results.append(process_record(record, owner_password))

    return {
        "statusCode": 200,
        "processed": results,
    }
