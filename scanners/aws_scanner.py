"""AWS credentials scanner using boto3 wrapped in asyncio.to_thread().

Since boto3 is synchronous, all AWS API calls are executed in a thread pool
via asyncio.to_thread() to avoid blocking the event loop. Checks STS, S3,
IAM, EC2, Lambda, SES, SNS, SQS, and Route53 for credential validity and
privilege scope.
"""

import asyncio
from typing import Any, Dict, Optional

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity

try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    ClientError = Exception  # type: ignore[assignment, misc]


class AWSScanner(BaseScanner):
    """Scanner for AWS access key credentials using boto3.

    Checks STS GetCallerIdentity, S3 ListBuckets, IAM GetUser, EC2
    DescribeInstances, Lambda ListFunctions, SES GetSendQuota, SNS
    ListTopics, SQS ListQueues, and Route53 ListHostedZones.
    """

    PROVIDER_NAME = "aws"
    CHECKS = [
        "AWS STS (GetCallerIdentity)",
        "AWS S3 (ListBuckets)",
        "AWS IAM (GetUser)",
        "AWS EC2 (DescribeInstances)",
        "AWS Lambda (ListFunctions)",
        "AWS SES (GetSendQuota)",
        "AWS SNS (ListTopics)",
        "AWS SQS (ListQueues)",
        "AWS Route53 (ListHostedZones)",
    ]

    def __init__(
        self,
        api_key: str,
        aws_secret: Optional[str] = None,
        region: str = "us-east-1",
        **kwargs: Any,
    ) -> None:
        """Initialize the AWS scanner.

        Args:
            api_key: AWS Access Key ID (AKIA... format).
            aws_secret: AWS Secret Access Key.
            region: AWS region name for API calls.
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)
        self.aws_secret = aws_secret
        self.region = region

    def _get_client(self, service: str) -> Any:
        """Create a boto3 client for the given AWS service.

        Args:
            service: AWS service name (e.g., 'sts', 's3', 'iam').

        Returns:
            A boto3 service client instance.
        """
        return boto3.client(
            service,
            aws_access_key_id=self.api_key,
            aws_secret_access_key=self.aws_secret,
            region_name=self.region,
        )

    def _check_boto3_call(self, service_name: str, action_name: str, call_fn: Any, severity: Severity) -> None:
        """Execute a boto3 call synchronously and log the result.

        Args:
            service_name: Human-readable AWS service name.
            action_name: The API action being called.
            call_fn: A callable that performs the boto3 API call.
            severity: Severity level for this check.
        """
        try:
            resp = call_fn()
            self.log_custom_result(
                service_name=f"{service_name} ({action_name})",
                status_text="VULNERABLE (ACCESS)",
                status_code=200,
                response_body=str(resp) if resp else "Success",
                url=f"boto3://{service_name}/{action_name}",
                severity=severity,
                color=self._c(Fore.GREEN),
            )
        except ClientError as e:
            self.log_custom_result(
                service_name=f"{service_name} ({action_name})",
                status_text="RESTRICTED (DENIED)",
                status_code=403,
                response_body=str(e),
                url=f"boto3://{service_name}/{action_name}",
                severity=Severity.INFO,
                color=self._c(Fore.RED),
            )
        except Exception as e:
            self.log_custom_result(
                service_name=f"{service_name} ({action_name})",
                status_text="CONNECTION ERROR",
                status_code=None,
                response_body=str(e),
                url=f"boto3://{service_name}/{action_name}",
                severity=Severity.CRITICAL,
                color=self._c(Fore.RED),
            )

    def _scan_sync(self) -> None:
        """Run all AWS checks synchronously (called via asyncio.to_thread)."""
        sts = self._get_client("sts")
        try:
            sts.get_caller_identity()
        except Exception:
            self.log_custom_result(
                service_name="AWS STS (GetCallerIdentity)",
                status_text="RESTRICTED (DENIED)",
                status_code=403,
                response_body="Auth failed — keys may be invalid or revoked",
                url="boto3://sts/GetCallerIdentity",
                severity=Severity.CRITICAL,
                color=self._c(Fore.RED),
            )
            print(
                f"{self._c(Fore.RED)}[!] Auth failed completely (STS rejected). Keys may be invalid or globally revoked.{Style.RESET_ALL}"
            )
            return

        self.log_custom_result(
            service_name="AWS STS (GetCallerIdentity)",
            status_text="VULNERABLE (ACCESS)",
            status_code=200,
            response_body="Successfully retrieved caller identity",
            url="boto3://sts/GetCallerIdentity",
            severity=Severity.CRITICAL,
            color=self._c(Fore.GREEN),
        )

        checks: Dict[str, Any] = {
            "AWS S3": ("ListBuckets", lambda: self._get_client("s3").list_buckets(), Severity.CRITICAL),
            "AWS IAM": ("GetUser", lambda: self._get_client("iam").get_user(), Severity.CRITICAL),
            "AWS EC2": ("DescribeInstances", lambda: self._get_client("ec2").describe_instances(), Severity.HIGH),
            "AWS Lambda": ("ListFunctions", lambda: self._get_client("lambda").list_functions(), Severity.HIGH),
            "AWS SES (Email)": ("GetSendQuota", lambda: self._get_client("ses").get_send_quota(), Severity.HIGH),
            "AWS SNS": ("ListTopics", lambda: self._get_client("sns").list_topics(), Severity.HIGH),
            "AWS SQS": ("ListQueues", lambda: self._get_client("sqs").list_queues(), Severity.HIGH),
            "AWS Route53": ("ListHostedZones", lambda: self._get_client("route53").list_hosted_zones(), Severity.HIGH),
        }

        for svc_name, (action, call_fn, sev) in checks.items():
            self._check_boto3_call(svc_name, action, call_fn, sev)

    async def scan(self) -> None:
        """Run all AWS credential checks via asyncio.to_thread()."""
        print(f"\n{self._c(Fore.CYAN)}=== AWS CREDENTIALS RECON ==={Style.RESET_ALL}\n")

        if not BOTO3_AVAILABLE:
            print(f"{self._c(Fore.RED)}[!] The 'boto3' Python library is required for AWS scanning.{Style.RESET_ALL}")
            print(f"{self._c(Fore.YELLOW)}Install it: pip install boto3{Style.RESET_ALL}")
            return

        if not self.api_key or not self.aws_secret:
            print(
                f"{self._c(Fore.RED)}[!] AWS scanning requires BOTH Access Key ID (-k) and Secret Access Key (--secret).{Style.RESET_ALL}"
            )
            return

        await asyncio.to_thread(self._scan_sync)
