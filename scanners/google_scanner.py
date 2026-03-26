import requests
from colorama import Fore, Style
from core.base_scanner import BaseScanner

class GoogleScanner(BaseScanner):
    def __init__(self, api_key, project_id=None, referer=None, jwt=None):
        super().__init__(api_key)
        self.project_id = project_id
        self.headers = {}
        if referer: self.headers['Referer'] = referer
        if jwt: self.headers['Authorization'] = f"Bearer {jwt}"

    def scan(self, collection_name="users", bucket_name=None):
        print(f"\n{Fore.CYAN}=== GOOGLE API RECON ==={Style.RESET_ALL}\n")

        # 1. GOOGLE CLOUD STORAGE
        target_bucket = bucket_name if bucket_name else self.project_id
        if target_bucket:
            gcs_url = f"https://storage.googleapis.com/storage/v1/b/{target_bucket}/o?key={self.api_key}"
            resp = requests.get(gcs_url, headers=self.headers)
            self.log_result(f"GCS Bucket (List: {target_bucket})", resp.status_code, resp)
        
        # 2. FIREBASE REMOTE CONFIG
        if self.project_id:
            rc_url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{self.project_id}/namespaces/firebase:fetch?key={self.api_key}"
            resp = requests.post(rc_url, headers=self.headers)
            self.log_result("Firebase Remote Config", resp.status_code, resp)
        
        # 3. FIRESTORE
        if self.project_id:
            fs_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{collection_name}?key={self.api_key}"
            resp = requests.get(fs_url, headers=self.headers)
            self.log_result(f"Firestore (List {collection_name})", resp.status_code, resp)
        
        # 4. IDENTITY TOOLKIT
        payload = {"email": "pentest_test_1337@example.com", "password": "Password123!", "returnSecureToken": True}
        resp = requests.post(f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}", json=payload, headers=self.headers)
        self.log_result("Identity Toolkit (SignUp)", resp.status_code, resp)

        # 5. GOOGLE MAPS (Static Map)
        resp = requests.get(f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=07&size=400x400&key={self.api_key}", headers=self.headers)
        self.log_result("Google Maps (Static Map)", resp.status_code, resp)

        # 6. CLOUD VISION API
        vision_url = f"https://vision.googleapis.com/v1/images:annotate?key={self.api_key}"
        vision_data = {"requests": [{"image": {"source": {"imageUri": "https://bit.ly/2u7S49G"}}, "features": [{"type": "LABEL_DETECTION"}]}]}
        resp = requests.post(vision_url, json=vision_data, headers=self.headers)
        self.log_result("Cloud Vision API", resp.status_code, resp)

        # 7. CLOUD TRANSLATE
        resp = requests.get(f"https://translation.googleapis.com/language/translate/v2?key={self.api_key}&q=hello&target=id", headers=self.headers)
        self.log_result("Cloud Translation API", resp.status_code, resp)

        # 8. YOUTUBE DATA API
        resp = requests.get(f"https://www.googleapis.com/youtube/v3/videos?id=7lC9W97K6n0&part=snippet&key={self.api_key}", headers=self.headers)
        self.log_result("YouTube Data API", resp.status_code, resp)

        # 9. CUSTOM SEARCH API
        resp = requests.get(f"https://www.googleapis.com/customsearch/v1?cx=017576662512468239146:omuauf_lfve&q=test&key={self.api_key}", headers=self.headers)
        self.log_result("Custom Search API", resp.status_code, resp)
        
        # 10. PAGESPEED INSIGHTS API
        resp = requests.get(f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://google.com&key={self.api_key}", headers=self.headers)
        self.log_result("PageSpeed Insights API", resp.status_code, resp)
        
        # 11. SAFE BROWSING API
        safebrowsing_data = {
            "client": {"clientId": "yourcompanyname", "clientVersion": "1.5.2"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["WINDOWS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "http://malware.testing.machine.test/testing/url/"}]
            }
        }
        resp = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}", json=safebrowsing_data, headers=self.headers)
        self.log_result("Safe Browsing API", resp.status_code, resp)
        
        # 12. GOOGLE DRIVE API V3
        resp = requests.get(f"https://www.googleapis.com/drive/v3/files?key={self.api_key}", headers=self.headers)
        self.log_result("Google Drive API", resp.status_code, resp)

        # 13. PLACES API
        resp = requests.get(f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={self.api_key}", headers=self.headers)
        self.log_result("Google Places API", resp.status_code, resp)
        
        # 14. DIRECTIONS API
        resp = requests.get(f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={self.api_key}", headers=self.headers)
        self.log_result("Google Directions API", resp.status_code, resp)
        
        # 15. GEOCODING API
        resp = requests.get(f"https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key={self.api_key}", headers=self.headers)
        self.log_result("Google Geocoding API", resp.status_code, resp)

        # 16. DISTANCE MATRIX API
        resp = requests.get(f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=Washington,DC&destinations=New+York+City,NY&key={self.api_key}", headers=self.headers)
        self.log_result("Google Distance Matrix API", resp.status_code, resp)

        # 17. FIREBASE CLOUD MESSAGING (FCM) LEGACY
        fcm_headers = {"Authorization": f"key={self.api_key}", "Content-Type": "application/json"}
        for k, v in self.headers.items(): fcm_headers[k] = v
        fcm_data = {"to": "/topics/test", "notification": {"title": "Test", "body": "Pentest"}}
        resp = requests.post("https://fcm.googleapis.com/fcm/send", json=fcm_data, headers=fcm_headers)
        self.log_result("FCM Legacy API", resp.status_code, resp)
