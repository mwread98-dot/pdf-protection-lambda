import json
import logging
import os
import pathlib
import subprocess
import tempfile
import urllib.parse
from typing import Any

import boto3
from botocore.exceptions import ClientError


LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger(__name__)

s3 = boto3.client("s3")
secrets_manager = boto3.client("secretsmanager")

OUTPUT_BUCKET = os.environ["OUTPUT_BUCKET"]
OWNER_PASSWORD_SECRET_ARN = os.environ["OWNER_PASSWORD_SECRET_ARN"]


class PdfProcessingError(Exception):
    """Raised when a PDF cannot be processed successfully."""


def get_owner_password() -> str:
    """
    Retrieve the PDF owner password from AWS Secrets Manager.

    Expected secret structure:
    {
        "purpose": "pdf-owner-password",
        "owner_password": "generated-password"
    }
    """
    try:
        response = secrets_manager.get_secret_value(
            SecretId=OWNER_PASSWORD_SECRET_ARN
        )
    except ClientError as exc:
        raise PdfProcessingError(
            "Unable to retrieve the PDF owner password from Secrets Manager."
        ) from exc

    secret_string = response.get("SecretString")

    if not secret_string:
        raise PdfProcessingError(
            "The PDF owner-password secret does not contain SecretString."
        )

    try:
        secret_value = json.loads(secret_string)
    except json.JSONDecodeError as exc:
        raise PdfProcessingError(
            "The PDF owner-password secret is not valid JSON."
        ) from exc

    owner_password = secret_value.get("owner_password")

    if not isinstance(owner_password, str) or not owner_password:
        raise PdfProcessingError(
            "The PDF owner-password secret does not contain a valid "
            "owner_password value."
        )

    return owner_password


def run_command(
    command: li*t[str],
    *,
    sensitive_value*: list[str] | None = None,
) -> su*process.CompletedProcess:
    """
*   Run a subprocess and raise PdfP*ocessingError if it fails.

    An* sensitive values are removed from*the version of the command
    wri*ten to logs.
    """
    sensitive_values = sensitive_values or []

    safe_command = command.copy()

    for index, argument in enumerate(safe_command):
        if argument in sensitive_values:
            safe_command[index] = "***REDACTED***"

    logger.info("Running command: %s", safe_command)

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=240,
        )
    except subprocess.TimeoutExpired as exc:
        raise PdfProcessingError(
            "qpdf did not complete within 240 seconds."
        ) from exc
    except OSError as exc:
        raise PdfProcessingError(
            "Unable to start qpdf."
        ) from exc

    if result.stdout:
        logger.info("Command stdout: %s", result.stdout.strip())

    if result.stderr:
        logger.info("Command stderr: %s", result.stderr.strip())

    if result.returncode != 0:
        raise PdfProcessingError(
            f"qpdf returned exit code {result.returncode}."
        )

    return result


def validate_input_pdf(input_path: pathlib.Path) -> None:
    """Check that the downloaded input is a structurally valid PDF."""
    run_command(
        [
            "qpdf",
            "--check",
            str(input_path),
        ]
    )


def protect_pdf(
    input_path: pathlib.Path,
    output_path: pathlib.Path,
    owner_password: str,
) -> None:
    """
    Encrypt a PDF with an empty user password and a secret owner password.

    The empty user password permits ordinary opening of the document.
    The owner password controls permissions and allows restrictions to
    be bypassed by an authorised owner.
    """
    command = [
        "qpdf",
        "--encrypt",
        "",
        owner_password,
        "256",
        "--print=none",
        "--modify=none",
        "--extract=n",
        "--annotate=n",
        "--form=n",
        "--assemble=n",
        "--",
        str(input_path),
        str(output_path),
    ]

    run_command(
        command,
        sensitive_values=[owner_password],
    )


def verify_output_pdf(
    output_path: pathlib.Path,
    owner_password: str,
) -> None:
    """Verify that the output is readable and encrypted."""
    run_command(
        [
            "qpdf",
            "--password=" + owner_password,
            "--check",
            str(output_path),
        ],
        sensitive_values=["--password=" + owner_password],
    )

    result = run_command(
        [
            "qpdf",
            "--password=" + owner_password,
            "--show-encryption",
            str(output_path),
        ],
        sensitive_values=["--password=" + owner_password],
    )

    encryption_details = result.stdout.lower()

    if "file is not encrypted" in encryption_details:
        raise PdfProcessingError(
            "qpdf created an output file that is not encrypted."
        )

    logger.info("Protected PDF encryption verification succeeded.")


def download_input_object(
    bucket: str,
    key: str,
    version_id: str | None,
    destination: pathlib.Path,
) -> None:
    """Download an input S3 object, including a specific version if supplied."""
    try:
        if version_id:
            s3.download_file(
                bucket,
                key,
                str(destination),
                ExtraArgs={
                    "VersionId": version_id,
                },
            )
        else:
            s3.download_file(
                bucket,
                key,
                str(destination),
            )
    except ClientError as exc:
        raise PdfProcessingError(
            f"Unable to download s3://{bucket}/{key}"
        ) from exc


def upload_output_object(
    key: str,
    source: pathlib.Path,
    input_bucket: str,
    input_version_id: str | None,
) -> None:
    """Upload a protected PDF to the output bucket."""
    metadata = {
        "pdf-protection": "qpdf-256-bit",
        "source-bucket": input_bucket,
    }

    if input_version_id:
        metadata["source-version-id"] = input_version_id

    try:
        s3.upload_file(
            str(source),
            OUTPUT_BUCKET,
            key,
            ExtraArgs={
                "ContentType": "application/pdf",
                "ServerSideEncryption": "AES256",
                "Metadata": metadata,
            },
        )
    except ClientError as exc:
        raise PdfProcessingError(
            f"Unable to upload s3://{OUTPUT_BUCKET}/{key}"
        ) from exc


def process_record(record: dict[str, Any]) -> dict[str, Any]:
    """Process one S3 event record."""
    event_name = record.get("eventName", "")

    if not event_name.startswith("ObjectCreated:"):
        logger.info("Skipping unsupported S3 event: %s", event_name)

        return {
            "status": "skipped",
            "reason": "unsupported-event",
            "event_name": event_name,
        }

    s3_data = record.get("s3", {})
    bucket_data = s3_data.get("bucket", {})
    object_data = s3_data.get("object", {})

    input_bucket = bucket_data.get("name")
    encoded_key = object_data.get("key")
    version_id = object_data.get("versionId")

    if not input_bucket or not encoded_key:
        raise PdfProcessingError(
            "The S3 event did not contain a bucket name and object key."
        )

    key = urllib.parse.unquote_plus(encoded_key)

    if not key.lower().endswith(".pdf"):
        logger.info(
            "Skipping non-PDF object: s3://%s/%s",
            input_bucket,
            key,
        )

        return {
            "status": "skipped",
            "reason": "not-a-pdf",
            "bucket": input_bucket,
            "key": key,
        }

    if input_bucket == OUTPUT_BUCKET:
        logger.warning(
            "Skipping an object from the output bucket to prevent a loop: "
            "s3://%s/%s",
            input_bucket,
            key,
        )

        return {
            "status": "skipped",
            "reason": "output-bucket-event",
            "bucket": input_bucket,
            "key": key,
        }

    logger.info(
        "Processing s3://%s/%s to s3://%s/%s",
        input_bucket,
        key,
        OUTPUT_BUCKET,
        key,
    )

    with tempfile.TemporaryDirectory(prefix="pdf-protection-") as temp_dir:
        temporary_directory = pathlib.Path(temp_dir)

        input_path = temporary_directory / "input.pdf"
        output_path = temporary_directory / "protected.pdf"

        download_input_object(
            input_bucket,
            key,
            version_id,
            input_path,
        )

        if not input_path.exists() or input_path.stat().st_size == 0:
            raise PdfProcessingError(
                "The downloaded input object is empty."
            )

        validate_input_pdf(input_path)

        owner_password = get_owner_password()

        protect_pdf(
            input_path,
            output_path,
            owner_password,
        )

        if not output_path.exists() or output_path.stat().st_size == 0:
            raise PdfProcessingError(
                "qpdf did not create a non-empty output file."
            )

        verify_output_pdf(
            output_path,
            owner_password,
        )

        upload_output_object(
            key,
            output_path,
            input_bucket,
            version_id,
        )

        output_size = output_path.stat().st_size

    logger.info(
        "Successfully wrote protected PDF to s3://%s/%s",
        OUTPUT_BUCKET,
        key,
    )

    return {
        "status": "processed",
        "input_bucket": input_bucket,
        "input_key": key,
        "input_version_id": version_id,
        "output_bucket": OUTPUT_BUCKET,
        "output_key": key,
        "output_size": output_size,
    }


def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """AWS Lambda entry point."""
    request_id = getattr(context, "aws_request_id", "unknown")

    logger.info(
        "Received invocation request ID %s with %s record(s).",
        request_id,
        len(event.get("Records", [])),
    )

    records = event.get("Records")

    if not isinstance(records, list) or not records:
        raise PdfProcessingError(
            "The event did not contain any S3 records."
        )

    results: list[dict[str, Any]] = []

    for record in records:
        results.append(process_record(record))

    return {
        "request_id": request_id,
        "record_count": len(records),
      
