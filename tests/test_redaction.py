"""Offline canary regressions for evidence and report redaction."""

import copy
import json
from pathlib import Path

import pytest

from core.base_scanner import BaseScanner, CheckOutcome, ExecutionStatus, ResponseData, ScanResult, Severity
from core.report_engine import ReportEngine


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_query_and_input_credentials_never_reach_reports(tmp_path, format_name):
    scanner = BaseScanner("B01-input-canary", no_color=True)
    response = ResponseData(200, {}, "https://provider.invalid/items?key=B01-query-canary&page=2", b"{}")
    scanner.log_result("Inventory B01-input-canary", 200, response)
    filename = str(tmp_path / f"report.{format_name}")
    getattr(ReportEngine, f"generate_{format_name}_report")(scanner, "test", filename)
    content = Path(filename).read_text(encoding="utf-8")
    assert "B01-query-canary" not in content
    assert "B01-input-canary" not in content
    assert "Inventory" in content
    assert "200" in content or format_name == "sarif"
    assert scanner.api_key == "B01-input-canary"


def test_response_evidence_is_sanitized_without_mutating_input(capsys):
    scanner = BaseScanner("B01-input-canary", no_color=True)
    body = {"items": [{"access_token": "B01-body-canary", "count": 3}], "reason": "permission denied"}
    headers = {
        "Set-Cookie": "session=B01-cookie-canary; HttpOnly",
        "X-Api-Key": "B01-header-canary",
        "Content-Type": "application/json",
    }
    response = ResponseData(403, headers, "https://provider.invalid/", json.dumps(body).encode(), "application/json")
    before = copy.deepcopy(response)
    scanner.log_result("Inventory", 403, response)
    evidence = json.dumps(scanner.raw_data)
    for secret in ("B01-body-canary", "B01-cookie-canary", "B01-header-canary"):
        assert secret not in evidence
    assert response == before
    assert scanner.raw_data[0]["response_body"]["items"][0]["count"] == 3
    assert scanner.raw_data[0]["response_body"]["reason"] == "permission denied"
    assert scanner.results[0]["status_code"] == 403
    assert scanner.results[0]["severity"] == "INFO"
    assert "Inventory" in capsys.readouterr().out


@pytest.mark.parametrize("custom", [False, True])
def test_error_and_custom_logging_redact_before_console_and_storage(capsys, custom):
    scanner = BaseScanner("B01-credential-canary", no_color=True)
    auth_canary = "B01-auth-canary"
    message = (
        "denied https://provider.invalid/?token=B01-error-canary "
        f"Authorization: Bearer {auth_canary} B01-credential-canary"
    )
    assert auth_canary in message
    if custom:
        scanner.log_custom_result(
            "Check B01-credential-canary", message, 403, {"client_secret": "B01-nested-canary", "count": 2}
        )
    else:
        scanner.log_error("Check B01-credential-canary", RuntimeError(message))
    output = capsys.readouterr().out + json.dumps(scanner.raw_data) + json.dumps(scanner.results)
    for secret in ("B01-credential-canary", "B01-error-canary", "B01-auth-canary", "B01-nested-canary"):
        assert secret not in output
    assert "denied" in output
    assert scanner.api_key == "B01-credential-canary"


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_writers_sanitize_directly_populated_evidence(tmp_path, capsys, format_name):
    scanner = BaseScanner("B01-input", no_color=True)
    scanner.scan_results = [
        ScanResult(
            check_id="",
            service_name="Inventory B01-body",
            provider="base",
            execution_status=ExecutionStatus.COMPLETED,
            outcome=CheckOutcome.RESTRICTED,
            reason="denied B01-input",
            status_code=403,
            url="https://provider.invalid/?subscription-key=B01-query",
            headers={"Set-Cookie": "sid=B01-cookie"},
            response_body={"access_token": "B01-body", "count": 2},
            auto_severity=Severity.INFO,
            custom_status_text="denied B01-input",
        )
    ]
    before = copy.deepcopy((scanner.results, scanner.raw_data))
    filename = str(tmp_path / f"report.{format_name}")
    getattr(ReportEngine, f"generate_{format_name}_report")(scanner, "test", filename)
    ReportEngine.display_console_summary(scanner, "test")
    output = Path(filename).read_text(encoding="utf-8") + capsys.readouterr().out
    for secret in ("B01-input", "B01-query", "B01-body", "B01-cookie"):
        assert secret not in output
    assert (scanner.results, scanner.raw_data) == before


def test_secondary_credentials_and_cookie_reflection_are_redacted(capsys):
    scanner = BaseScanner("B01-primary", no_color=True)
    scanner.aws_secret = "B01-secondary"
    response = ResponseData(
        200,
        {"Set-Cookie": "sid=B01-cookie; HttpOnly"},
        "https://provider.invalid/",
        b'{"message":"B01-cookie B01-secondary"}',
        "application/json",
    )
    scanner.log_result("Inventory", 200, response)
    output = capsys.readouterr().out + json.dumps(scanner.raw_data)
    assert "B01-cookie" not in output
    assert "B01-secondary" not in output


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_complete_canary_matrix_in_each_output(tmp_path, capsys, format_name):
    scanner = BaseScanner("B01-input-matrix", no_color=True)
    body = {"items": [{"refresh_token": "B01-body-matrix", "count": 4}], "reason": "denied"}
    response = ResponseData(
        403,
        {"Authorization": "Bearer B01-header-matrix", "Set-Cookie": "sid=B01-cookie-matrix"},
        "https://provider.invalid/?key=B01-query-matrix&page=2",
        json.dumps(body).encode(),
        "application/json",
    )
    scanner.log_result("Inventory", 403, response)
    scanner.log_error("Error check", "denied token=B01-error-matrix B01-input-matrix")
    scanner.log_custom_result("Custom check", "RESTRICTED", 403, {"client_secret": "B01-custom-matrix", "count": 1})
    filename = str(tmp_path / f"report.{format_name}")
    getattr(ReportEngine, f"generate_{format_name}_report")(scanner, "test", filename)
    output = Path(filename).read_text(encoding="utf-8") + capsys.readouterr().out
    for location in ("input", "body", "header", "cookie", "query", "error", "custom"):
        assert f"B01-{location}-matrix" not in output
    for check in ("Inventory", "Error check", "Custom check"):
        assert check in output
    assert len(scanner.results) == 3
    assert scanner.raw_data[0]["response_body"]["items"][0]["count"] == 4


def test_encoded_url_and_json_text_use_same_redaction():
    from core.redaction import Sanitizer

    source = {
        "url": "https://user:pass@provider.invalid/?%61pi_key=B01%2Bencoded",
        "text": '{"clientSecret":"B01-json-text","count":5}',
    }
    sanitizer = Sanitizer(source)
    cleaned = sanitizer.clean(source)
    assert "user:pass" not in cleaned["url"]
    assert "B01%2Bencoded" not in cleaned["url"]
    assert "B01-json-text" not in cleaned["text"]
    assert json.loads(cleaned["text"])["count"] == 5


def test_header_token_reflection_and_decoded_query_are_redacted():
    from core.redaction import Sanitizer

    source = {
        "headers": {"Authorization": "Bearer B01-reflected"},
        "url": "https://provider.invalid/?key=B01%2Bvalue",
        "message": "B01-reflected B01+value",
    }
    cleaned = Sanitizer(source).clean(source)
    assert "B01-reflected" not in cleaned["message"]
    assert "B01+value" not in cleaned["message"]


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
@pytest.mark.parametrize("representation", ["python", "json", "assignment"])
def test_error_representations_redact_before_all_outputs(tmp_path, capsys, format_name, representation):
    secret = "DUMMY_ERROR_SECRET"
    payload = {"access_token": secret, "reason": "denied"}
    message = {
        "python": str(payload),
        "json": json.dumps(payload),
        "assignment": f"access_token={secret} reason=denied",
    }[representation]
    scanner = BaseScanner("dummy-input", no_color=True)
    scanner.log_error("Error check", RuntimeError(message))
    console = capsys.readouterr().out
    assert secret not in console
    assert secret not in json.dumps(scanner.raw_data)
    assert "denied" in console
    assert "denied" in scanner.raw_data[0]["response_body"]
    filename = str(tmp_path / f"error.{format_name}")
    getattr(ReportEngine, f"generate_{format_name}_report")(scanner, "test", filename)
    content = Path(filename).read_text(encoding="utf-8")
    assert secret not in content
    assert "Error check" in content
    assert "CONNECTION ERROR" in content


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_cookie_attributes_do_not_corrupt_evidence(tmp_path, capsys, format_name):
    url = "https://provider.invalid/items?page=2"
    reason = "denied / provider.invalid Lax Wed, 09 Jun 2027 10:18:14 GMT 3600"
    headers = {
        "Set-Cookie": "sid=dummy-session; Path=/; Domain=provider.invalid; SameSite=Lax; "
        "Expires=Wed, 09 Jun 2027 10:18:14 GMT; Max-Age=3600; Secure; HttpOnly"
    }
    scanner = BaseScanner("dummy-input", no_color=True)
    response = ResponseData(
        403,
        headers,
        url,
        json.dumps({"reason": reason, "reflection": "dummy-session", "count": 2}).encode(),
        "application/json",
    )
    before = copy.deepcopy(response)
    scanner.log_result("Inventory", 403, response)
    assert scanner.raw_data[0]["url"] == url
    assert scanner.raw_data[0]["response_body"]["reason"] == reason
    assert scanner.raw_data[0]["response_body"]["count"] == 2
    assert "dummy-session" not in json.dumps(scanner.raw_data)
    assert response == before
    filename = str(tmp_path / f"cookie.{format_name}")
    getattr(ReportEngine, f"generate_{format_name}_report")(scanner, "test", filename)
    content = Path(filename).read_text(encoding="utf-8")
    assert url in content
    assert "dummy-session" not in content + capsys.readouterr().out
    assert "Inventory" in content


def test_short_cookie_credential_is_still_redacted():
    from core.redaction import Sanitizer

    source = {
        "headers": {"Set-Cookie": "sid=Z; Path=/; SameSite=Lax"},
        "message": "credential Z",
        "url": "https://provider.invalid/",
    }
    cleaned = Sanitizer(source).clean(source)
    assert cleaned["message"] == "credential [REDACTED]"
    assert cleaned["url"] == source["url"]


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_original_mask_lookalike_never_leaks(tmp_path, format_name):
    secret = "abcdefgh" + "." * 4
    scanner = BaseScanner(secret)
    scanner.log_custom_result("Inventory", "RESTRICTED", 403, {"api_key": secret, "reason": "reflected " + secret})
    assert secret not in json.dumps(scanner.raw_data)
    path = tmp_path / ("lookalike." + format_name)
    getattr(ReportEngine, "generate_" + format_name + "_report")(scanner, "test", str(path))
    assert secret not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_direct_writer_does_not_trust_plain_marker_shape(tmp_path, format_name):
    secret = "abcdefgh" + "." * 4
    scanner = BaseScanner(secret)
    scanner.scan_results = [
        ScanResult(
            check_id="",
            service_name="Inventory " + secret,
            provider="base",
            execution_status=ExecutionStatus.COMPLETED,
            outcome=CheckOutcome.RESTRICTED,
            reason="RESTRICTED",
            status_code=403,
            url="https://provider.invalid/?key=" + secret,
            headers={},
            response_body={"api_key": secret},
            auto_severity=Severity.INFO,
            custom_status_text="RESTRICTED",
        )
    ]
    path = tmp_path / ("direct." + format_name)
    getattr(ReportEngine, "generate_" + format_name + "_report")(scanner, "test", str(path))
    assert secret not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_private_error_reflections_never_show_prefix(tmp_path, capsys, format_name):
    secret = "LONG_PASSWORD_" + "123456789"
    message = f"password={secret} reflected {secret} Authorization: Bearer {secret}"
    assert secret in message
    scanner = BaseScanner("dummy-key")
    scanner.log_error("Inventory", message)
    assert secret[:8] not in capsys.readouterr().out
    assert secret[:8] not in json.dumps(scanner.raw_data)
    path = tmp_path / ("private." + format_name)
    getattr(ReportEngine, "generate_" + format_name + "_report")(scanner, "test", str(path))
    assert secret[:8] not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("origin", ["assignment", "query", "header"])
def test_private_classification_follows_all_reflections(origin):
    from core.redaction import Sanitizer

    secret = "LONG_PASSWORD_" + "123456789"
    source = {
        "assignment": f"password={secret} reflected {secret} Authorization: Bearer {secret}",
        "query": {
            "url": f"https://provider.invalid/?password={secret}",
            "message": f"reflected {secret}",
            "Authorization": f"Bearer {secret}",
        },
        "header": {
            "headers": {"password": secret},
            "message": f"reflected {secret}",
            "Authorization": f"Bearer {secret}",
        },
    }[origin]
    cleaned = Sanitizer(source).clean(source)
    assert secret[:8] not in str(cleaned)
    assert "[REDACTED]" in str(cleaned)


def test_short_secret_does_not_replace_letters_inside_metadata():
    from core.redaction import Sanitizer

    source = {"api_key": "Z", "reason": "AZURE denied", "reflection": "credential Z"}
    clean = Sanitizer(source).clean(source)
    assert clean["api_key"] == "[REDACTED]"
    assert clean["reason"] == "AZURE denied"
    assert clean["reflection"] == "credential [REDACTED]"


@pytest.mark.parametrize("origin", ["assignment", "cookie"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_private_value_policy_wins_across_output_routes(tmp_path, capsys, origin, reverse, format_name):
    from core.redaction import Sanitizer

    secret = "LONG_PASSWORD_" + "123456789"
    pairs = [
        ("message", f"access_token={secret} reflected {secret}"),
        ("Authorization", f"Bearer {secret}"),
        ("reason", "denied"),
        ("Set-Cookie", f"password={secret}; Path=/") if origin == "cookie" else ("password", secret),
    ]
    source = dict(reversed(pairs) if reverse else pairs)
    before = copy.deepcopy(source)
    clean = Sanitizer(source).clean(source)
    assert secret[:8] not in json.dumps(clean)
    assert clean["reason"] == "denied"
    assert source == before
    scanner = BaseScanner("dummy-input")
    scanner.log_custom_result("Inventory", "RESTRICTED", 403, source)
    scanner.log_error("Error", source)
    assert secret[:8] not in capsys.readouterr().out
    assert secret[:8] not in json.dumps(scanner.raw_data)
    path = tmp_path / ("private-policy." + format_name)
    getattr(ReportEngine, "generate_" + format_name + "_report")(scanner, "test", str(path))
    assert secret[:8] not in path.read_text(encoding="utf-8")


def test_prefix_mask_is_idempotent_and_metadata_is_preserved():
    from core.redaction import Sanitizer

    source = {
        "apiKey": "abcdefgh1234567890",
        "password": "password123456789",
        "token_type": "Bearer",
        "token_count": 42,
        "monkey": "banana",
    }
    clean = Sanitizer(source).clean(source)
    assert clean["apiKey"] == "abcdefgh...."
    assert clean["password"] == "[REDACTED]"
    assert clean["token_type"] == "Bearer"
    assert clean["token_count"] == 42
    assert clean["monkey"] == "banana"
    assert Sanitizer(clean).clean(clean) == clean


def test_prefix_policy_reaches_url_text_and_cookie_metadata():
    from core.redaction import Sanitizer

    source = {
        "api_key": "abcdefgh1234567890",
        "url": "https://provider.invalid/?key=abcdefgh1234567890&page=2",
        "message": "credential abcdefgh1234567890 dark",
        "Cookie": "preference=dark; sid=abcdefgh1234567890",
    }
    clean = Sanitizer(source).clean(source)
    assert clean["url"] == "https://provider.invalid/?key=abcdefgh....&page=2"
    assert clean["message"] == "credential abcdefgh.... dark"
    assert "preference=dark" in clean["Cookie"]
    assert "sid=abcdefgh...." in clean["Cookie"]
    assert Sanitizer(clean).clean(clean) == clean


@pytest.mark.parametrize("name", ["api_key", "apiKey", "API-KEY", "access_token", "x-api-key"])
def test_mask_field_aliases(name):
    from core.redaction import Sanitizer

    source = {name: "abcdefgh1234567890"}
    assert Sanitizer(source).clean(source)[name] == "abcdefgh...."


def test_bounded_structure_and_unknown_cookie_metadata():
    from core.redaction import Sanitizer

    source = {"Cookie": "preference=dark", "reason": "dark mode", "access_token": None, "token_count": 2}
    assert Sanitizer(source).clean(source) == source
    assert "OMITTED" in Sanitizer().text("x" * 70000)


@pytest.mark.parametrize("kind", ["Bearer", "Basic"])
def test_auth_scheme_and_reflection_are_consistent(kind):
    from core.redaction import Sanitizer

    token = "abcdefgh1234567890"
    source = {"Authorization": f"{kind} {token}", "message": f"reflected {token}"}
    masked = "abcdefgh...." if kind == "Bearer" else "[REDACTED]"
    clean = Sanitizer(source).clean(source)
    assert clean == {"Authorization": f"{kind} {masked}", "message": f"reflected {masked}"}
    assert Sanitizer(clean).clean(clean) == clean


def test_known_credential_reflection_in_url_path_and_query():
    from core.redaction import Sanitizer

    token = "abcdefgh1234567890"
    source = {"url": f"https://provider.invalid/{token}?other={token}&key={token}"}
    clean = Sanitizer(source, secrets=(token,)).clean(source)
    assert token not in clean["url"]
    assert clean["url"] == "https://provider.invalid/abcdefgh....?other=abcdefgh....&key=abcdefgh...."


def test_deep_collection_is_bounded():
    from core.redaction import Sanitizer

    source = {"access_token": "abcdefgh1234567890"}
    for _ in range(1500):
        source = {"child": source}
    clean = Sanitizer(source).clean(source)
    assert "OMITTED" in str(clean)


@pytest.mark.parametrize(
    "value", ["a'b\\c\"d" + "1234567890", "秘密🔐+token/" + "1234567890", "abcdefgh1234567890...."]
)
@pytest.mark.parametrize("representation", ["mapping", "json", "repr"])
def test_structured_special_characters_and_marker_lookalike(value, representation):
    from core.redaction import Sanitizer

    source = {"access_token": value, "reason": "denied", "count": 2}
    original = (
        source if representation == "mapping" else json.dumps(source) if representation == "json" else repr(source)
    )
    cleaned = Sanitizer(original).clean(original)
    decoded = cleaned if isinstance(cleaned, dict) else json.loads(cleaned)
    assert decoded["access_token"] == value[:8] + "...."
    assert decoded["reason"] == "denied"
    assert decoded["count"] == 2


def test_json_metadata_uses_same_mask_policy(tmp_path):
    scanner = BaseScanner("abcdefgh1234567890")
    path = tmp_path / "report.json"
    ReportEngine.generate_json_report(scanner, "test", str(path))
    metadata = json.loads(path.read_text())["scan_metadata"]
    assert metadata["api_key_scanned"] == "abcdefgh...."


@pytest.mark.parametrize("secret", ["Z", "abcdefgh1234567890"])
def test_overlapping_secrets_do_not_corrupt_masks(secret):
    from core.redaction import Sanitizer

    longer = secret + "1234567890abcdef"
    source = {"api_key": longer, "access_token": secret, "message": f"{longer} {secret}"}
    clean = Sanitizer(source).clean(source)
    assert clean["message"] == longer[:8] + ".... " + (secret[:8] + "...." if len(secret) >= 16 else "[REDACTED]")
    assert Sanitizer(clean).clean(clean) == clean


@pytest.mark.parametrize(
    "source",
    [
        {"password": "full-password-123456789", "url": "https://provider.invalid/?password=full-password-123456789"},
        {"password": "full-password-123456789", "message": "password=full-password-123456789"},
    ],
)
def test_password_is_never_prefix_masked(source):
    from core.redaction import Sanitizer

    clean = Sanitizer(source).clean(source)
    assert "full-pas" not in str(clean)


@pytest.mark.parametrize(
    "text", ["[" * 4000, "'" * 60000, "{" + "x" * 66000], ids=["deep-malformed", "quotes", "oversized"]
)
def test_long_malformed_text_is_bounded(text):
    from core.redaction import Sanitizer

    clean = Sanitizer(text).clean(text)
    assert isinstance(clean, str)
    assert len(clean) <= 65536


def test_known_cookie_credential_is_independent_of_field_order():
    from core.redaction import Sanitizer

    token = "abcdefgh1234567890"
    source = {"Cookie": "custom=" + token + "; preference=dark", "api_key": token, "reason": "dark mode"}
    clean = Sanitizer(source).clean(source)
    assert "custom=abcdefgh...." in clean["Cookie"]
    assert clean["reason"] == "dark mode"


def test_password_and_basic_text_keep_no_prefix():
    from core.redaction import Sanitizer

    text = "denied password=abcdefgh1234567890 reason=denied"
    clean = Sanitizer(text).text(text)
    assert clean == "denied password=[REDACTED] reason=denied"


def test_bearer_text_uses_token_prefix_not_scheme_prefix():
    from core.redaction import Sanitizer

    message = "denied Authorization: Bearer abcdefgh1234567890"
    assert Sanitizer(message).text(message) == "denied Authorization: Bearer abcdefgh...."


def test_url_userinfo_keeps_host_path_and_safe_query():
    from core.redaction import Sanitizer

    source = {"url": "https://dummy:password@provider.invalid/items?page=2"}
    assert Sanitizer(source).clean(source)["url"] == "https://[REDACTED]@provider.invalid/items?page=2"


def test_sensitive_cookie_password_has_no_prefix():
    from core.redaction import Sanitizer

    source = {"password": "abcdefgh1234567890", "Cookie": "custom=abcdefgh1234567890; preference=dark"}
    assert "custom=[REDACTED]" in Sanitizer(source).clean(source)["Cookie"]


@pytest.mark.parametrize("value", [None, "", 1234, False])
def test_sensitive_scalar_shapes(value):
    from core.redaction import Sanitizer

    source = {"access_token": value, "count": 2}
    clean = Sanitizer(source).clean(source)
    assert clean["access_token"] == (value if value is None or value == "" else "[REDACTED]")
    assert clean["count"] == 2


def test_query_repeated_encoding_and_plus_are_single_pass():
    from core.redaction import Sanitizer

    source = {"url": "https://provider.invalid/items?%61pi_key=abcdefgh%2B123456789&apiKey=abcdefgh+123456789&page=2"}
    clean = Sanitizer(source).clean(source)
    assert clean["url"] == "https://provider.invalid/items?%61pi_key=abcdefgh....&apiKey=abcdefgh....&page=2"
    assert Sanitizer(clean).clean(clean) == clean


def test_fallback_and_sensitive_tree_have_explicit_limits():
    from core.redaction import Sanitizer

    assert "OMITTED" in Sanitizer().text("a" * 5000)
    deep = {"leaf": "dummy"}
    for _ in range(1500):
        deep = {"child": deep}
    source = {"credentials": deep}
    assert "REDACTED" in str(Sanitizer(source).clean(source))


_SESSION_COOKIE_ALIASES = [
    "JSESSIONID",
    "PHPSESSID",
    "connect.sid",
    "ASP.NET_SessionId",
    "NODESESSID",
    "express.sessid",
    "sessionid",
    "_session_id",
]

_SESSION_NEGATIVE_CONTROLS = [
    "token_count",
    "token_type",
    "monkey",
    "preference",
    "csrf",
    "theme",
    "lang",
    "count",
    "page",
    "status",
]


@pytest.mark.parametrize("name", _SESSION_COOKIE_ALIASES)
def test_session_cookie_aliases_classified_sensitive(name):
    from core.redaction import sensitive

    assert sensitive(name), f"{name!r} must be sensitive"


@pytest.mark.parametrize("name", _SESSION_NEGATIVE_CONTROLS)
def test_session_cookie_negative_controls_not_sensitive(name):
    from core.redaction import sensitive

    assert not sensitive(name), f"{name!r} must not be sensitive"


@pytest.mark.parametrize("name", _SESSION_COOKIE_ALIASES)
def test_session_cookie_alias_value_masked_in_cookie_header(name):
    from core.redaction import Sanitizer

    token = "abcdefgh1234567890"
    source = {"Cookie": f"{name}={token}; preference=dark", "reason": "dark mode"}
    clean = Sanitizer(source).clean(source)
    assert token not in clean["Cookie"], f"{name} cookie value leaked whole"
    assert f"{name}=abcdefgh...." in clean["Cookie"], f"{name} value not prefix-masked"
    assert "preference=dark" in clean["Cookie"], "non-secret cookie corrupted"
    assert clean["reason"] == "dark mode"


@pytest.mark.parametrize("name", _SESSION_COOKIE_ALIASES)
def test_session_cookie_alias_value_masked_in_set_cookie(name):
    from core.redaction import Sanitizer

    token = "abcdefgh1234567890"
    source = {"Set-Cookie": f"{name}={token}; Path=/; HttpOnly"}
    clean = Sanitizer(source).clean(source)
    assert token not in clean["Set-Cookie"], f"{name} set-cookie value leaked whole"
    assert "abcdefgh...." in clean["Set-Cookie"], f"{name} value not prefix-masked"
    assert "Path=/" in clean["Set-Cookie"], "Set-Cookie attribute corrupted"


@pytest.mark.parametrize("name", _SESSION_COOKIE_ALIASES)
def test_session_cookie_alias_reflection_redacted(name):
    from core.redaction import Sanitizer

    token = "abcdefgh1234567890"
    source = {"Cookie": f"{name}={token}", "message": f"reflected {token} in body"}
    clean = Sanitizer(source).clean(source)
    assert token not in clean["message"], f"{name} token leaked via reflection"
    assert "abcdefgh...." in clean["message"], "reflection not prefix-masked"


@pytest.mark.parametrize("name", _SESSION_COOKIE_ALIASES)
def test_session_cookie_alias_masking_is_idempotent(name):
    from core.redaction import Sanitizer

    token = "abcdefgh1234567890"
    source = {"Cookie": f"{name}={token}; preference=dark", "reason": "dark mode"}
    clean = Sanitizer(source).clean(source)
    assert Sanitizer(clean).clean(clean) == clean


def test_session_cookie_short_value_fully_redacted():
    from core.redaction import Sanitizer

    source = {"Cookie": "JSESSIONID=abc; preference=dark"}
    clean = Sanitizer(source).clean(source)
    assert "JSESSIONID=[REDACTED]" in clean["Cookie"], "short session id not fully redacted"
    assert "preference=dark" in clean["Cookie"]


def test_session_cookie_negative_controls_preserved_in_cookie_context():
    from core.redaction import Sanitizer

    source = {
        "Cookie": "preference=dark; theme=light; csrf=abc123; lang=en",
        "token_count": 2,
        "monkey": "patch",
        "status": "ok",
    }
    clean = Sanitizer(source).clean(source)
    assert "preference=dark" in clean["Cookie"]
    assert "theme=light" in clean["Cookie"]
    assert "csrf=abc123" in clean["Cookie"]
    assert "lang=en" in clean["Cookie"]
    assert clean["token_count"] == 2
    assert clean["monkey"] == "patch"
    assert clean["status"] == "ok"
