import smtplib, ssl
from email.message import EmailMessage
from dotenv import load_dotenv
import os

load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

msg = EmailMessage()
msg["From"] = EMAIL_USER
msg["To"] = EMAIL_USER
msg["Subject"] = "Test from Stark"
msg.set_content("Bu test xati.")

context = ssl.create_default_context()

try:
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
        server.starttls(context=context)
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        print("✅ Email yuborildi!")
except Exception as e:
    print("❌ Xato:", e)
