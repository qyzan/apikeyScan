"""B11 acceptance tests: validasi prerequisite credential provider.

Tests prove:
- Criterion 1: Twilio does not start requests with empty secret/wrong account SID;
  AWS without credential pair produces clear input error.
- Criterion 2: Unsupported options are rejected/explained before request.
- Criterion 3: Tests use dummy constructor/fake client, not real auth.
- Criterion 4: No secret values printed when explaining missing fields.
"""

from __future__ import annotations

import pytest

from core.base_scanner import CheckOutcome, ExecutionStatus
from core.redaction import sensitive


class TestTwilioPrerequisiteValidation:
    """Criterion 1: Twilio does not start request with empty secret/wrong SID."""

    @pytest.mark.asyncio
    async def test_missing_account_sid_skips(self):
        """Twilio with no account_sid → SKIPPED, no HTTP requests."""
        from scanners.twilio_scanner import TwilioScanner

        scanner = TwilioScanner("SK" + "a" * 32, api_secret="secret", no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.outcome == CheckOutcome.SKIPPED
        assert result.execution_status == ExecutionStatus.SKIPPED
        assert "Account SID" in result.reason or "Account SID" in str(result.response_body)

    @pytest.mark.asyncio
    async def test_wrong_account_sid_format_skips(self):
        """Twilio with account_sid not starting with 'AC' → SKIPPED."""
        from scanners.twilio_scanner import TwilioScanner

        scanner = TwilioScanner(
            "SK" + "a" * 32,
            account_sid="XX" + "b" * 32,
            api_secret="secret",
            no_color=True,
        )
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.outcome == CheckOutcome.SKIPPED
        assert "AC" in str(result.response_body)

    @pytest.mark.asyncio
    async def test_missing_api_secret_skips(self):
        """Twilio with no api_secret → SKIPPED, no HTTP requests."""
        from scanners.twilio_scanner import TwilioScanner

        scanner = TwilioScanner(
            "SK" + "a" * 32,
            account_sid="AC" + "b" * 32,
            no_color=True,
        )
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.outcome == CheckOutcome.SKIPPED
        assert "secret" in str(result.response_body).lower()

    @pytest.mark.asyncio
    async def test_aws_secret_alias_works_for_api_secret(self):
        """Twilio accepts aws_secret as alias for api_secret (--secret reuse)."""
        from scanners.twilio_scanner import TwilioScanner

        scanner = TwilioScanner(
            "SK" + "a" * 32,
            account_sid="AC" + "b" * 32,
            aws_secret="my_secret",
            no_color=True,
        )
        assert scanner.api_secret == "my_secret"

    @pytest.mark.asyncio
    async def test_valid_prerequisites_proceed_to_requests(self):
        """Twilio with valid account_sid + api_secret → proceeds (not skipped).

        Uses a mock session to avoid real HTTP. The scanner should attempt
        requests, not skip.
        """
        from unittest.mock import AsyncMock, MagicMock

        from scanners.twilio_scanner import TwilioScanner

        scanner = TwilioScanner(
            "SK" + "a" * 32,
            account_sid="AC" + "b" * 32,
            api_secret="my_secret",
            no_color=True,
        )

        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.url = "https://api.twilio.com/2010-04-01/Accounts/ACtest"
        mock_response.read = AsyncMock(return_value=b'{"error": "auth failed"}')

        class FakeCtx:
            async def __aenter__(self):
                return mock_response

            async def __aexit__(self, *args):
                return False

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=FakeCtx())
        scanner._session = mock_session

        await scanner.scan()

        assert scanner.planned_checks == 5
        for result in scanner.scan_results:
            assert result.outcome != CheckOutcome.SKIPPED

    @pytest.mark.asyncio
    async def test_no_secret_leakage_in_skip_message(self):
        """Skip messages must not contain the actual key or secret values."""
        from scanners.twilio_scanner import TwilioScanner

        test_key = "SK" + "a" * 32
        test_secret = "super_secret_value_12345"
        scanner = TwilioScanner(
            test_key,
            account_sid="AC" + "b" * 32,
            api_secret=test_secret,
            no_color=True,
        )
        scanner.account_sid = ""
        await scanner.scan()

        result = scanner.scan_results[0]
        body_str = str(result.response_body)
        assert test_secret not in body_str
        assert test_key not in body_str


class TestAWSCredentialValidation:
    """Criterion 1: AWS without credential pair → clear input error."""

    @pytest.mark.asyncio
    async def test_aws_missing_secret_skips(self):
        """AWS without secret → SKIPPED with clear message."""
        from scanners.aws_scanner import AWSScanner

        scanner = AWSScanner("AKIA" + "A" * 16, no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.outcome == CheckOutcome.SKIPPED
        assert "secret" in str(result.response_body).lower() or "credential" in str(result.response_body).lower()

    @pytest.mark.asyncio
    async def test_aws_missing_key_skips(self):
        """AWS with empty key → SKIPPED."""
        from scanners.aws_scanner import AWSScanner

        scanner = AWSScanner("", aws_secret="secret", no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.outcome == CheckOutcome.SKIPPED

    @pytest.mark.asyncio
    async def test_aws_no_secret_leakage_in_skip_message(self):
        """AWS skip message must not contain the actual key or secret."""
        from scanners.aws_scanner import AWSScanner

        test_key = "AKIA" + "A" * 16
        scanner = AWSScanner(test_key, no_color=True)
        await scanner.scan()

        result = scanner.scan_results[0]
        body_str = str(result.response_body)
        assert test_key not in body_str


class TestUnrecognizedParamsWarning:
    """Criterion 2: Unsupported options rejected/explained before request."""

    def test_github_with_secret_warns(self, capsys):
        """GitHub scanner with --secret → warning about unrecognized param."""
        from scanners.github_scanner import GitHubScanner

        GitHubScanner("ghp_test", aws_secret="mysecret", api_secret="mysecret", no_color=True)
        captured = capsys.readouterr()
        assert "does not recognize" in captured.out

    def test_openai_with_project_id_warns(self, capsys):
        """OpenAI scanner with project_id → warning."""
        from scanners.openai_scanner import OpenAIScanner

        OpenAIScanner("sk-test", project_id="myproj", no_color=True)
        captured = capsys.readouterr()
        assert "does not recognize" in captured.out

    def test_stripe_with_bucket_warns(self, capsys):
        """Stripe scanner with bucket_name → warning."""
        from scanners.stripe_scanner import StripeScanner

        StripeScanner("sk_live_test", bucket_name="mybucket", no_color=True)
        captured = capsys.readouterr()
        assert "does not recognize" in captured.out

    def test_no_warning_without_extra_params(self, capsys):
        """Scanner with only recognized params → no warning."""
        from scanners.github_scanner import GitHubScanner

        GitHubScanner("ghp_test", no_color=True)
        captured = capsys.readouterr()
        assert "does not recognize" not in captured.out

    def test_google_with_project_id_no_warning(self, capsys):
        """Google scanner with project_id → no warning (it's a recognized param)."""
        from scanners.google_scanner import GoogleScanner

        GoogleScanner("AIza_test", project_id="myproj", no_color=True)
        captured = capsys.readouterr()
        assert "does not recognize" not in captured.out

    def test_aws_with_secret_no_unrecognized_warning(self, capsys):
        """AWS scanner with aws_secret → no unrecognized warning (it's recognized)."""
        from scanners.aws_scanner import AWSScanner

        AWSScanner("AKIA_test", aws_secret="secret", no_color=True)
        captured = capsys.readouterr()
        assert "does not recognize" not in captured.out

    def test_twilio_with_account_sid_no_unrecognized_warning(self, capsys):
        """Twilio with account_sid + api_secret → no unrecognized warning."""
        from scanners.twilio_scanner import TwilioScanner

        TwilioScanner(
            "SK" + "a" * 32,
            account_sid="AC" + "b" * 32,
            api_secret="secret",
            no_color=True,
        )
        captured = capsys.readouterr()
        assert "does not recognize" not in captured.out


class TestAWSTransportWarningExtended:
    """Criterion 2: AWS transport warning includes proxy/user_agent."""

    def test_aws_with_proxy_warns(self, capsys):
        """AWS scanner with proxy → transport warning includes proxy."""
        from scanners.aws_scanner import AWSScanner

        AWSScanner("AKIA_test", aws_secret="secret", proxy="http://proxy:8080", no_color=True)
        captured = capsys.readouterr()
        assert "does not support" in captured.out
        assert "proxy" in captured.out

    def test_aws_with_user_agent_warns(self, capsys):
        """AWS scanner with user_agent → transport warning includes user_agent."""
        from scanners.aws_scanner import AWSScanner

        AWSScanner("AKIA_test", aws_secret="secret", user_agent="custom", no_color=True)
        captured = capsys.readouterr()
        assert "does not support" in captured.out
        assert "user_agent" in captured.out

    def test_aws_without_proxy_no_transport_warning(self, capsys):
        """AWS scanner without proxy/user_agent → no transport warning for them."""
        from scanners.aws_scanner import AWSScanner

        AWSScanner("AKIA_test", aws_secret="secret", no_color=True)
        captured = capsys.readouterr()
        assert "does not support" not in captured.out


class TestAccountSidRedaction:
    """Criterion 4: account_sid is treated as sensitive for redaction."""

    def test_account_sid_is_sensitive(self):
        """sensitive('account_sid') → True."""
        assert sensitive("account_sid") is True

    def test_accountsid_is_sensitive(self):
        """sensitive('accountsid') → True."""
        assert sensitive("accountsid") is True

    def test_account_sid_in_error_redacted(self):
        """account_sid value should be redacted in error messages."""
        from core.redaction import Sanitizer

        test_sid = "AC" + "a" * 32
        sanitizer = Sanitizer({"account_sid": test_sid})
        result = sanitizer.text(f"Error with account_sid={test_sid}")
        assert test_sid not in result
