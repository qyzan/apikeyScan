"""Google Cloud & Workspace API scanner with 22+ async checks.

Covers GCS, Firebase RTDB/RemoteConfig, Firestore, Identity Toolkit,
Maps suite, Vision, Translate, YouTube, Custom Search, PageSpeed,
Safe Browsing, Drive, Places, Directions, Geocoding, Distance Matrix,
FCM, Secret Manager, KMS, Cloud Build, Cloud SQL, and Gemini.
"""

from typing import Any

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class GoogleScanner(BaseScanner):
    """Scanner for Google Cloud Platform and Workspace API keys.

    Checks 22+ Google services for key validity and access scope,
    including critical infrastructure like GCS, Firebase, Firestore,
    Identity Toolkit, Secret Manager, and KMS.
    """

    PROVIDER_NAME = "google"
    CHECKS = [
        "GCS Bucket List",
        "Firebase Remote Config (Template)",
        "Firebase RTDB (-default-rtdb)",
        "Firebase RTDB (Legacy)",
        "Firestore List Documents",
        "Identity Toolkit (SignUp)",
        "Google Maps (Static Map)",
        "Cloud Vision API",
        "Cloud Translation API",
        "YouTube Data API",
        "Custom Search API",
        "PageSpeed Insights API",
        "Safe Browsing API",
        "Google Drive API",
        "Google Places API",
        "Google Directions API",
        "Google Geocoding API",
        "Google Distance Matrix API",
        "FCM HTTP v1 API",
        "Google Secret Manager",
        "Google Cloud KMS",
        "Google Cloud Build",
        "Google Cloud SQL",
        "Google Gemini API",
    ]

    def __init__(
        self,
        api_key: str,
        project_id: str | None = None,
        referer: str | None = None,
        jwt: str | None = None,
        collection_name: str = "users",
        bucket_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the Google scanner.

        Args:
            api_key: The Google API key to test.
            project_id: Optional GCP project ID for project-scoped checks.
            referer: Optional HTTP Referer header for bypass testing.
            jwt: Optional JWT bearer token for auth-protected endpoints.
            collection_name: Firestore collection name to query.
            bucket_name: GCS bucket name to test (defaults to project_id).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)
        self.project_id = project_id
        self.collection_name = collection_name
        self.bucket_name = bucket_name
        self.headers: dict[str, str] = {}
        if referer:
            self.headers["Referer"] = referer
        if jwt:
            self.headers["Authorization"] = f"Bearer {jwt}"

    async def scan(self) -> None:
        """Run all Google API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== GOOGLE API RECON ==={Style.RESET_ALL}\n")

        checks: list[Any] = [
            self._check_identity_toolkit(),
            self._check_maps_static(),
            self._check_vision(),
            self._check_translate(),
            self._check_youtube(),
            self._check_custom_search(),
            self._check_pagespeed(),
            self._check_safe_browsing(),
            self._check_drive(),
            self._check_places(),
            self._check_directions(),
            self._check_geocoding(),
            self._check_distance_matrix(),
            self._check_gemini(),
        ]

        target_bucket = self.bucket_name or self.project_id
        if target_bucket:
            checks.append(self._check_gcs_bucket(target_bucket))

        if self.project_id:
            checks.extend(
                [
                    self._check_firebase_remote_config(),
                    self._check_firebase_rtdb_default(),
                    self._check_firebase_rtdb_legacy(),
                    self._check_firestore(),
                    self._check_fcm_v1(),
                    self._check_secret_manager(),
                    self._check_cloud_kms(),
                    self._check_cloud_build(),
                    self._check_cloud_sql(),
                ]
            )

        await self._run_checks(checks)

    async def _check_gcs_bucket(self, target_bucket: str) -> None:
        """Check GCS bucket listing access."""
        svc = f"GCS Bucket (List: {target_bucket})"
        url = f"https://storage.googleapis.com/storage/v1/b/{target_bucket}/o?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_firebase_remote_config(self) -> None:
        """Check Firebase Remote Config template download access."""
        svc = "Firebase Remote Config (Template)"
        url = (
            f"https://firebaseremoteconfig.googleapis.com/v1/projects/{self.project_id}/remoteConfig?key={self.api_key}"
        )
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_firebase_rtdb_default(self) -> None:
        """Check Firebase Realtime Database access (default-rtdb instance)."""
        svc = "Firebase RTDB (-default-rtdb)"
        url = f"https://{self.project_id}-default-rtdb.firebaseio.com/.json?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_firebase_rtdb_legacy(self) -> None:
        """Check Firebase Realtime Database access (legacy URL format)."""
        svc = "Firebase RTDB (Legacy)"
        url = f"https://{self.project_id}.firebaseio.com/.json?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_firestore(self) -> None:
        """Check Firestore document listing access."""
        svc = f"Firestore (List {self.collection_name})"
        url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{self.collection_name}?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_identity_toolkit(self) -> None:
        """Check Identity Toolkit signUp — account creation capability."""
        svc = "Identity Toolkit (SignUp)"
        test_email = "pentest_test_1337@example.com"
        test_pass = "Password123!"
        payload = {"email": test_email, "password": test_pass, "returnSecureToken": True}
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        ok, resp = await self._safe_post(svc, url, headers=self.headers or None, json_body=payload)
        if ok and resp:
            label = svc
            if resp.status == 200:
                label += f" [Created: {test_email} : {test_pass}]"
            self.log_result(label, resp.status, resp, severity=Severity.CRITICAL)

    async def _check_maps_static(self) -> None:
        """Check Google Maps Static API access."""
        svc = "Google Maps (Static Map)"
        url = f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=07&size=400x400&key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_vision(self) -> None:
        """Check Cloud Vision API annotation access."""
        svc = "Cloud Vision API"
        url = f"https://vision.googleapis.com/v1/images:annotate?key={self.api_key}"
        data = {
            "requests": [
                {
                    "image": {"source": {"imageUri": "https://bit.ly/2u7S49G"}},
                    "features": [{"type": "LABEL_DETECTION"}],
                }
            ]
        }
        ok, resp = await self._safe_post(svc, url, headers=self.headers or None, json_body=data)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_translate(self) -> None:
        """Check Cloud Translation API access."""
        svc = "Cloud Translation API"
        url = f"https://translation.googleapis.com/language/translate/v2?key={self.api_key}&q=hello&target=id"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_youtube(self) -> None:
        """Check YouTube Data API v3 access."""
        svc = "YouTube Data API"
        url = f"https://www.googleapis.com/youtube/v3/videos?id=7lC9W97K6n0&part=snippet&key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_custom_search(self) -> None:
        """Check Custom Search API access."""
        svc = "Custom Search API"
        url = (
            f"https://www.googleapis.com/customsearch/v1?cx=017576662512468239146:omuauf_lfve&q=test&key={self.api_key}"
        )
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_pagespeed(self) -> None:
        """Check PageSpeed Insights API access."""
        svc = "PageSpeed Insights API"
        url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://google.com&key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_safe_browsing(self) -> None:
        """Check Safe Browsing API threat matching access."""
        svc = "Safe Browsing API"
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        data = {
            "client": {"clientId": "yourcompanyname", "clientVersion": "1.5.2"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["WINDOWS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "http://malware.testing.machine.test/testing/url/"}],
            },
        }
        ok, resp = await self._safe_post(svc, url, headers=self.headers or None, json_body=data)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_drive(self) -> None:
        """Check Google Drive API v3 file listing access."""
        svc = "Google Drive API"
        url = f"https://www.googleapis.com/drive/v3/files?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_places(self) -> None:
        """Check Google Places API findplacefromtext access."""
        svc = "Google Places API"
        url = (
            f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json"
            f"?input=Museum%20of%20Contemporary%20Art%20Australia"
            f"&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry"
            f"&key={self.api_key}"
        )
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_directions(self) -> None:
        """Check Google Directions API access."""
        svc = "Google Directions API"
        url = f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_geocoding(self) -> None:
        """Check Google Geocoding API access."""
        svc = "Google Geocoding API"
        url = f"https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_distance_matrix(self) -> None:
        """Check Google Distance Matrix API access."""
        svc = "Google Distance Matrix API"
        url = f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=Washington,DC&destinations=New+York+City,NY&key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_fcm_v1(self) -> None:
        """Check Firebase Cloud Messaging HTTP v1 send access."""
        svc = "FCM HTTP v1 API"
        url = f"https://fcm.googleapis.com/v1/projects/{self.project_id}/messages:send?key={self.api_key}"
        fcm_headers = {**self.headers, "Content-Type": "application/json"}
        if "Authorization" not in fcm_headers:
            fcm_headers["Authorization"] = f"Bearer {self.api_key}"
        data = {"message": {"topic": "test", "notification": {"title": "Test", "body": "Pentest"}}}
        ok, resp = await self._safe_post(svc, url, headers=fcm_headers, json_body=data)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_secret_manager(self) -> None:
        """Check Google Secret Manager listing access."""
        svc = "Google Secret Manager"
        url = f"https://secretmanager.googleapis.com/v1/projects/{self.project_id}/secrets?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.CRITICAL)

    async def _check_cloud_kms(self) -> None:
        """Check Google Cloud KMS key ring listing access."""
        svc = "Google Cloud KMS"
        url = f"https://cloudkms.googleapis.com/v1/projects/{self.project_id}/locations/global/keyRings?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_cloud_build(self) -> None:
        """Check Google Cloud Build listing access."""
        svc = "Google Cloud Build"
        url = f"https://cloudbuild.googleapis.com/v1/projects/{self.project_id}/builds?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_cloud_sql(self) -> None:
        """Check Google Cloud SQL instance listing access."""
        svc = "Google Cloud SQL"
        url = f"https://sqladmin.googleapis.com/v1/projects/{self.project_id}/instances?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_gemini(self) -> None:
        """Check Google Gemini (Generative Language) API model listing access."""
        svc = "Google Gemini API"
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={self.api_key}"
        ok, resp = await self._safe_get(svc, url, headers=self.headers or None)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)
