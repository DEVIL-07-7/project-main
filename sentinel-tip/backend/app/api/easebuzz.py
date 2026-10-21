import os
import hashlib
import urllib.parse
from dotenv import load_dotenv

load_dotenv()

EASEBUZZ_KEY = os.getenv("EASEBUZZ_KEY", "2PBP7IABZ2")
EASEBUZZ_SALT = os.getenv("EASEBUZZ_SALT", "DAH88E3UWQ")
EASEBUZZ_ENV = os.getenv("EASEBUZZ_ENV", "test")


def generate_hash(data: dict) -> str:
    hash_string = (
        f"{data['key']}|{data['txnid']}|{data['amount']}|{data['productinfo']}|"
        f"{data['firstname']}|{data['email']}|||||||||||{EASEBUZZ_SALT}"
    )
    return hashlib.sha512(hash_string.encode("utf-8")).hexdigest()


def get_easebuzz_payment_url(
    user_email: str,
    user_name: str,
    txnid: str,
    amount: str,
    phone: str = "9999999999",
) -> str:
    base_url = (
        "https://testpay.easebuzz.in/payment/initiateLink"
        if EASEBUZZ_ENV == "test"
        else "https://pay.easebuzz.in/payment/initiateLink"
    )

    payload = {
        "key": EASEBUZZ_KEY,
        "txnid": txnid,
        "amount": amount,
        "productinfo": "ThreatOps Enterprise Subscription",
        "firstname": user_name or "SOC Analyst",
        "phone": phone,
        "email": user_email,
        "surl": "http://localhost:5173/?success=true",
        "furl": "http://localhost:5173/?canceled=true",
    }
    payload["hash"] = generate_hash(payload)
    return f"{base_url}?{urllib.parse.urlencode(payload)}"