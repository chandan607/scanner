import json
import subprocess
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
# import sys
# import os
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main import app

client = TestClient(app)


@pytest.fixture
def mock_trivy_output():
    return {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "PkgName": "libssl",
                        "VulnerabilityID": "CVE-2021-1234",
                        "InstalledVersion": "1.1.1f",
                        "FixedVersion": "1.1.1g",
                        "Severity": "HIGH",
                        "Title": "OpenSSL vulnerability"
                    }
                ]
            }
        ]
    }


def test_scan_success(mock_trivy_output):
    mock_completed_process = MagicMock()
    mock_completed_process.stdout = json.dumps(mock_trivy_output)
    mock_completed_process.returncode = 0

    with patch("subprocess.run", return_value=mock_completed_process):
        response = client.post("/scan", json={"image": "nginx"})
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data
        assert data["vulnerabilities"][0]["Package"] == "libssl"
        assert data["vulnerabilities"][0]["Severity"] == "HIGH"


def test_scan_failure():
    mock_process = MagicMock()
    mock_process.stderr = "Trivy failed"
    mock_process.returncode = 1

    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
        returncode=1, cmd="trivy", stderr="Trivy failed"
    )):
        response = client.post("/scan", json={"image": "nginx"})
        assert response.status_code == 500
        assert "detail" in response.json()
        assert response.json()["detail"] == "Trivy failed"
