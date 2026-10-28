import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import endpoints
from security import rate_limiter


class CourseSphereSecurityAndSRETests(unittest.TestCase):
    def setUp(self):
        rate_limiter.reset()
        self.client = endpoints.app.test_client()

    def test_sql_injection_mitigated_on_courses_routes(self):
        """Ensures SQL injection payloads are treated as literal values and do not leak rows."""
        r_valid = self.client.get("/courses/department/CS")
        self.assertEqual(r_valid.status_code, 200)
        self.assertGreaterEqual(len(r_valid.get_json()), 1)

        sqli_payload = "CS' OR '1'='1"
        r_sqli = self.client.get(f"/courses/department/{sqli_payload}")
        self.assertEqual(r_sqli.status_code, 404)
        self.assertEqual(r_sqli.get_json(), {"error": "No courses found for this department"})

    def test_protected_routes_reject_unauthenticated_and_url_tokens(self):
        """Ensures protected routes require Authorization Bearer header and reject query-string JWTs."""
        r_query = self.client.post("/users/query", json={"query": "CS 2110"})
        self.assertEqual(r_query.status_code, 401)

        r_url_jwt = self.client.get("/users/info?id_token=leaked_jwt_in_url")
        self.assertEqual(r_url_jwt.status_code, 401)

        r_hash = self.client.post("/hash", json={"data": "test"})
        self.assertEqual(r_hash.status_code, 401)

        r_chat = self.client.delete("/chats/chat_123")
        self.assertEqual(r_chat.status_code, 401)

    @patch("endpoints.Firebase.get_user_info")
    @patch("endpoints.Firebase.verify_id_token")
    def test_authenticated_access_enforces_token_uid(self, mock_verify, mock_get_info):
        """Ensures verified token UID is used to isolate user data access."""
        mock_verify.return_value = {"uid": "user_authenticated_01"}
        mock_get_info.return_value = {"majors": ["CS"], "college": "Engineering"}

        headers = {"Authorization": "Bearer valid_mock_jwt_token"}
        r_info = self.client.get("/users/info", headers=headers)
        self.assertEqual(r_info.status_code, 200)
        self.assertEqual(r_info.get_json()["majors"], ["CS"])
        mock_get_info.assert_called_once_with("user_authenticated_01")

    def test_cors_allowlist_and_security_headers(self):
        """Verifies CORS blocks unauthorized origins and HTTP security headers are present."""
        r_evil = self.client.options(
            "/users/create",
            headers={
                "Origin": "https://malicious-site.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertIsNone(r_evil.headers.get("Access-Control-Allow-Origin"))

        r_allowed = self.client.options(
            "/users/create",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(
            r_allowed.headers.get("Access-Control-Allow-Origin"),
            "http://localhost:5173",
        )

        r_courses = self.client.get("/courses")
        self.assertEqual(r_courses.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r_courses.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("max-age=31536000", r_courses.headers.get("Strict-Transport-Security", ""))
        self.assertIn("default-src 'self'", r_courses.headers.get("Content-Security-Policy", ""))

    @patch("endpoints.Firebase.set_user_info")
    @patch("endpoints.Firebase.verify_id_token")
    def test_input_validation_sanitization_and_path_traversal(self, mock_verify, mock_set_info):
        """Verifies input sanitization on user profile and path traversal rejection on chat_id."""
        mock_verify.return_value = {"uid": "user_01"}
        headers = {"Authorization": "Bearer valid_mock_jwt_token"}

        # Reject invalid chat_id with special characters
        r_bad_chat = self.client.delete("/chats/invalid$chat.id", headers=headers)
        self.assertEqual(r_bad_chat.status_code, 400)

        # Sanitize HTML entities in user profile fields
        r_profile = self.client.post(
            "/users/info",
            headers=headers,
            json={
                "majors": ["Computer Science"],
                "minors": [],
                "courses": ["CS 2110"],
                "college": "Engineering",
                "year": "2026",
                "about": "<script>alert(1)</script>",
            },
        )
        self.assertEqual(r_profile.status_code, 200)
        saved_payload = mock_set_info.call_args[0][1]
        self.assertEqual(saved_payload["about"], "&lt;script&gt;alert(1)&lt;/script&gt;")

    def test_rate_limiting_returns_429(self):
        """Verifies rate limiting blocks excessive requests on /users/create (limit 5/min)."""
        for _ in range(5):
            resp = self.client.post(
                "/users/create", json={"email": "invalid-email-format"}
            )
            self.assertEqual(resp.status_code, 400)

        blocked = self.client.post(
            "/users/create", json={"email": "invalid-email-format"}
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertIsNotNone(blocked.headers.get("Retry-After"))

    def test_sre_health_and_prometheus_metrics_endpoints(self):
        """Verifies /health and /metrics endpoints for SRE observability."""
        r_health = self.client.get("/health")
        self.assertEqual(r_health.status_code, 200)
        health_data = r_health.get_json()
        self.assertEqual(health_data["status"], "healthy")
        self.assertEqual(health_data["database"], "connected")
        self.assertIn("instance_id", health_data)

        r_metrics = self.client.get("/metrics")
        self.assertEqual(r_metrics.status_code, 200)
        metrics_text = r_metrics.get_data(as_text=True)
        self.assertIn("http_requests_total", metrics_text)
        self.assertIn("http_request_duration_seconds_bucket", metrics_text)
        self.assertIn("auth_failures_total", metrics_text)


if __name__ == "__main__":
    unittest.main()
