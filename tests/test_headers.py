import requests

TARGET = "https://onediversity.agency"

REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def test_security_headers():

    response = requests.get(TARGET)

    missing = []

    for header in REQUIRED_HEADERS:
        if header not in response.headers:
            missing.append(header)

    assert not missing, (
        f"Missing Security Headers: {missing}"
    )
