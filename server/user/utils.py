from cryptography.fernet import Fernet
import secrets
import base64
# from .models import Team

def getReferralCode() -> str:
    num = secrets.randbits(32)
    b64_bytes = num.to_bytes(4, byteorder='big', signed=False)
    b64_string = base64.urlsafe_b64encode(b64_bytes).decode()[:6]

    return "".join(b64_string)



    