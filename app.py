import os
import time
import secrets
import string
import smtplib
import ssl

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
FLASK_SECRET = os.getenv("FLASK_SECRET") or secrets.token_hex(16)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

CODE_TTL = 10 * 60  # kodning amal qilish vaqti (sekund)

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# Fayllar uchun papka (agar yo'q bo'lsa yaratamiz)
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "profile_pics")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# In-memory stores (demo). Production: almashtiring DB bilan
PENDING = {}   # email -> {code, expires_at, name, password_hash}
USERS = {}     # email -> {name, password_hash, created_at, profile_image, age, profession, gender}


def generate_code(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def send_code_email(to_email: str, code: str, name: str = ""):
    """
    Xavfsiz SMTP orqali kod yuboradi (STARTTLS).
    """
    if not EMAIL_USER or not EMAIL_PASS:
        app.logger.error("EMAIL_USER yoki EMAIL_PASS .env da topilmadi.")
        raise RuntimeError("SMTP sozlamalari topilmadi. .env ni tekshiring.")

    subject = "StarK — Ro'yxatdan o'tish kodi"
    body = f"Salom {name or 'Foydalanuvchi'},\n\nSizning StarK tasdiqlash kodingiz:\n\n{code}\n\nU {CODE_TTL // 60} daqiqa davomida amal qiladi.\n\nAgar siz so'ramagan bo'lsangiz, e'tibor bermang.\n— StarK team"

    msg = EmailMessage()
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
    app.logger.info("Email yuborildi: %s", to_email)


@app.before_request
def log_request():
    # diagnostika uchun (terminalda ko'rish mumkin)
    app.logger.debug("REQ PATH: %s METHOD: %s", request.path, request.method)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        # Basic validation
        if not email or "@" not in email:
            flash("Iltimos, haqiqiy email kiriting.", "danger")
            return redirect(url_for("register"))
        if not password or len(password) < 6:
            flash("Parol kamida 6 ta belgi bo'lishi kerak.", "danger")
            return redirect(url_for("register"))

        if email in USERS:
            flash("Bu email allaqachon ro'yxatdan o'tgan. Iltimos kirish qiling.", "warning")
            return redirect(url_for("login"))

        # generate code, store pending
        code = generate_code(6)
        expires_at = time.time() + CODE_TTL
        password_hash = generate_password_hash(password)
        PENDING[email] = {
            "code": code,
            "expires_at": expires_at,
            "name": name,
            "password_hash": password_hash,
            "resend_allowed_at": time.time() + 60  # 60s ichida resendni cheklash
        }

        try:
            send_code_email(email, code, name)
        except Exception as e:
            app.logger.exception("Email yuborishda xato")
            flash("Kod yuborishda xatolik yuz berdi. SMTP sozlamalarini tekshiring.", "danger")
            return redirect(url_for("register"))

        session["pending_email"] = email
        flash("Tasdiqlash kodi emailingizga yuborildi. Iltimos tekshiring.", "info")
        return redirect(url_for("verify"))

    return render_template("register.html")


@app.route("/resend_code")
def resend_code():
    email = session.get("pending_email")
    if not email or email not in PENDING:
        flash("Yuborish uchun email topilmadi.", "warning")
        return redirect(url_for("register"))

    pending = PENDING[email]
    now = time.time()
    if now < pending.get("resend_allowed_at", 0):
        wait = int(pending["resend_allowed_at"] - now)
        flash(f"Iltimos {wait} soniya kuting, keyin qayta yuborishingiz mumkin.", "warning")
        return redirect(url_for("verify"))

    code = generate_code(6)
    pending["code"] = code
    pending["expires_at"] = now + CODE_TTL
    pending["resend_allowed_at"] = now + 60
    try:
        send_code_email(email, code, pending.get("name", ""))
    except Exception:
        app.logger.exception("Resend yuborishda xato")
        flash("Kodni qayta yuborishda xato.", "danger")
        return redirect(url_for("verify"))

    flash("Yangi kod yuborildi.", "info")
    return redirect(url_for("verify"))


@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("pending_email")
    if not email:
        flash("Ro'yxatdan o'tishni boshlang.", "warning")
        return redirect(url_for("register"))

    pending = PENDING.get(email)
    if not pending:
        flash("Tasdiqlash ma'lumotlari topilmadi yoki muddati tugagan.", "danger")
        return redirect(url_for("register"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        if time.time() > pending["expires_at"]:
            PENDING.pop(email, None)
            session.pop("pending_email", None)
            flash("Kod muddati tugadi. Iltimos yana ro'yxatdan o'ting.", "danger")
            return redirect(url_for("register"))
        if code == pending["code"]:
            # create user
            USERS[email] = {
                "name": pending.get("name") or "Foydalanuvchi",
                "password_hash": pending["password_hash"],
                "created_at": time.time(),
                "profile_image": None,
                "age": None,
                "profession": None,
                "gender": None
            }
            PENDING.pop(email, None)
            session.pop("pending_email", None)
            session["user_email"] = email
            flash("Ro'yxatdan muvaffaqiyatli o'tdingiz. Xush kelibsiz!", "success")
            return redirect(url_for("profile"))
        else:
            flash("Kod noto'g'ri. Iltimos qayta tekshiring.", "danger")
            return redirect(url_for("verify"))

    return render_template("verify.html", email=email, ttl=CODE_TTL)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = USERS.get(email)
        if user and check_password_hash(user["password_hash"], password):
            session["user_email"] = email
            flash("Tizimga muvaffaqiyatli kirdingiz.", "success")
            return redirect(url_for("profile"))
        flash("Email yoki parol noto'g'ri.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/profile")
def profile():
    user_email = session.get("user_email")
    if not user_email:
        flash("Profilga kirish uchun tizimga kiring.", "warning")
        return redirect(url_for("login"))
    user = USERS.get(user_email, {})
    return render_template("profile.html", user=user, email=user_email)


@app.route("/videos")
def videos():
    video_list = [
        {"title": "Python asoslari", "filename": "python_intro.mp4"},
        {"title": "HTML darsi", "filename": "html_tutorial.mp4"},
        {"title": "CSS dizayn", "filename": "css_design.mp4"},
        {"title": "JavaScript boshlanishi", "filename": "js_start.mp4"},
    ]
    return render_template("videos.html", videos=video_list)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/edit_profile", methods=['GET', 'POST'])
def edit_profile():
    user_email = session.get("user_email")
    if not user_email:
        flash("Profilni tahrirlash uchun tizimga kiring.", "warning")
        return redirect(url_for("login"))

    user = USERS.get(user_email)
    if not user:
        flash("Foydalanuvchi ma'lumotlari topilmadi.", "danger")
        return redirect(url_for("login"))

    if request.method == 'POST':
        # Yangilash maydonlari
        full_name = request.form.get('full_name') or user.get('name')
        age = request.form.get('age') or user.get('age')
        profession = request.form.get('profession') or user.get('profession')
        gender = request.form.get('gender') or user.get('gender')

        # Faylni saqlash
        file = request.files.get('profile_image')
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(upload_path)
            user['profile_image'] = filename

        # Saqlash
        user['name'] = full_name
        user['age'] = age
        user['profession'] = profession
        user['gender'] = gender

        USERS[user_email] = user
        flash('Profil yangilandi!', 'success')
        return redirect(url_for('profile'))

    # GET: sahifani ko'rsatish
    return render_template('edit_profile.html', user=user, email=user_email)


@app.route("/logout")
def logout():
    session.clear()
    flash("Siz tizimdan chiqdingiz.", "info")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)

