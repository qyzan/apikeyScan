import sys
from colorama import Fore, Style
from core.base_scanner import BaseScanner

try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

class AWSScanner(BaseScanner):
    def __init__(self, api_key, aws_secret):
        super().__init__(api_key)
        self.aws_secret = aws_secret

    def _get_client(self, service):
        return boto3.client(
            service,
            aws_access_key_id=self.api_key,
            aws_secret_access_key=self.aws_secret,
            region_name='us-east-1'
        )

    def log_boto3_result(self, service_name, action_name, success, response_obj):
        status_code = 200 if success else 403
        if success:
            status_text = "VULNERABLE (ACCESS)"
            color = Fore.GREEN
        else:
            status_text = "RESTRICTED (DENIED)"
            color = Fore.RED

        print(f"{color}[{status_text}]{Style.RESET_ALL} Checking {service_name} ({action_name})...")

        self.results.append({
            "service": f"{service_name} ({action_name})",
            "status_text": status_text,
            "status_code": status_code,
            "color": color
        })
        
        clean_resp = "Access Denied / Exception occurred"
        if success:
            try:
                clean_resp = str(response_obj)
            except:
                clean_resp = "Valid Response Received (Unserializable)"

        self.raw_data.append({
            "service": service_name,
            "url": f"boto3://{service_name}/{action_name}",
            "status_code": status_code,
            "headers": {},
            "response_body": clean_resp
        })

    def scan(self):
        print(f"\n{Fore.CYAN}=== AWS CREDENTIALS RECON ==={Style.RESET_ALL}\n")
        
        if not BOTO3_AVAILABLE:
            print(f"{Fore.RED}[!] The 'boto3' Python library is critically required for AWS scanning.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please install it by running: pip install boto3{Style.RESET_ALL}")
            sys.exit(1)

        if not self.api_key or not self.aws_secret:
            print(f"{Fore.RED}[!] AWS scanning requires BOTH Access Key ID (-k) and Secret Access Key (--secret).{Style.RESET_ALL}")
            sys.exit(1)

        # 1. STS GetCallerIdentity
        sts = self._get_client('sts')
        try:
            resp = sts.get_caller_identity()
            self.log_boto3_result("AWS STS", "GetCallerIdentity", True, resp)
        except Exception as e:
            self.log_boto3_result("AWS STS", "GetCallerIdentity", False, str(e))
            print(f"{Fore.RED}[!] Auth failed completely (STS rejected). Keys may be invalid or globally revoked.{Style.RESET_ALL}")
            return

        # 2. S3 ListBuckets
        s3 = self._get_client('s3')
        try:
            resp = s3.list_buckets()
            self.log_boto3_result("AWS S3", "ListBuckets", True, "Successfully retrieved bucket list")
        except Exception as e:
            self.log_boto3_result("AWS S3", "ListBuckets", False, str(e))

        # 3. IAM GetUser
        iam = self._get_client('iam')
        try:
            resp = iam.get_user()
            self.log_boto3_result("AWS IAM", "GetUser", True, "Successfully retrieved user profile")
        except Exception as e:
            self.log_boto3_result("AWS IAM", "GetUser", False, str(e))

        # 4. EC2 DescribeInstances
        ec2 = self._get_client('ec2')
        try:
            resp = ec2.describe_instances()
            self.log_boto3_result("AWS EC2", "DescribeInstances", True, "Successfully fetched EC2 instances")
        except Exception as e:
            self.log_boto3_result("AWS EC2", "DescribeInstances", False, str(e))

        # 5. Lambda ListFunctions
        awslambda = self._get_client('lambda')
        try:
            resp = awslambda.list_functions()
            self.log_boto3_result("AWS Lambda", "ListFunctions", True, "Successfully fetched Lambda functions")
        except Exception as e:
            self.log_boto3_result("AWS Lambda", "ListFunctions", False, str(e))

        # 6. SES GetSendQuota
        ses = self._get_client('ses')
        try:
            resp = ses.get_send_quota()
            self.log_boto3_result("AWS SES (Email)", "GetSendQuota", True, resp)
        except Exception as e:
            self.log_boto3_result("AWS SES (Email)", "GetSendQuota", False, str(e))

        # 7. SNS ListTopics
        sns = self._get_client('sns')
        try:
            resp = sns.list_topics()
            self.log_boto3_result("AWS SNS", "ListTopics", True, resp)
        except Exception as e:
            self.log_boto3_result("AWS SNS", "ListTopics", False, str(e))

        # 8. SQS ListQueues
        sqs = self._get_client('sqs')
        try:
            resp = sqs.list_queues()
            self.log_boto3_result("AWS SQS", "ListQueues", True, resp)
        except Exception as e:
            self.log_boto3_result("AWS SQS", "ListQueues", False, str(e))

        # 9. Route53 ListHostedZones
        route53 = self._get_client('route53')
        try:
            resp = route53.list_hosted_zones()
            self.log_boto3_result("AWS Route53", "ListHostedZones", True, resp)
        except Exception as e:
            self.log_boto3_result("AWS Route53", "ListHostedZones", False, str(e))
