import os
import sqlite3
import hmac
import hashlib
import base64
from dataclasses import dataclass
import customtkinter as ctk


# ---------------------------
# Security: password hashing
# ---------------------------
def _hash_password(password: str, salt: bytes | None = None, iterations: int = 200_000) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_b64, dk_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters_s)
        salt = base64.b64decode(salt_b64.encode())
        dk_expected = base64.b64decode(dk_b64.encode())
        dk_check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(dk_expected))
        return hmac.compare_digest(dk_expected, dk_check)
    except Exception:
        return False


# ---------------------------
# DB layer
# ---------------------------
@dataclass(frozen=True)
class AuthResult:
    ok: bool
    message: str

class AuthDB:
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA foreign_keys=ON;")
        return con

    def _init_db(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
            """)

    def register(self, username: str, password: str) -> AuthResult:
        username = username.strip()
        if len(username) < 3:
            return AuthResult(False, "Username must be at least 3 characters.")

        if len(password) < 6:
            return AuthResult(False, "Password must be at least 6 characters.")

        password_hash = _hash_password(password)
        try:
            with self._connect() as con:
                con.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?);",
                    (username, password_hash),
                )
            return AuthResult(True, "Account created successfully.")
        except sqlite3.IntegrityError:
            return AuthResult(False, "Username already exists.")
        except Exception:
            return AuthResult(False, "Registration failed.")

    def login(self, username: str, password: str) -> AuthResult:
        username = username.strip()
        if not username:
            return AuthResult(False, "Username is required.")
        if not password:
            return AuthResult(False, "Password is required.")

        try:
            with self._connect() as con:
                row = con.execute(
                    "SELECT password_hash FROM users WHERE username = ?;",
                    (username,),
                ).fetchone()
            if not row:
                return AuthResult(False, "Invalid username or password.")

            stored_hash = row[0]
            if _verify_password(password, stored_hash):
                return AuthResult(True, "Login successful.")
            return AuthResult(False, "Invalid username or password.")
        except Exception:
            return AuthResult(False, "Login failed.")


class LoginRegisterApp(ctk.CTk):
    def __init__(self, db: AuthDB):
        super().__init__()
        self._db = db

        self.title("Login / Register")
        self.geometry("460x400")
        self.resizable(False, False)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        root_pad_x = 18

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=root_pad_x, pady=(18, 8))

        title_font = ctk.CTkFont(size=20, weight="bold")
        subtitle_font = ctk.CTkFont(size=12)

        ctk.CTkLabel(header, text="Welcome", font=title_font).pack(anchor="w")
        ctk.CTkLabel(
            header,
            text="Sign in to continue or create a new account.",
            font=subtitle_font,
        ).pack(anchor="w", pady=(2, 0))

        self._tabs = ctk.CTkTabview(self)
        self._tabs.pack(fill="both", expand=True, padx=root_pad_x, pady=(8, 10))

        self._login_tab = self._tabs.add("Login")
        self._register_tab = self._tabs.add("Register")

        self._build_login_tab()
        self._build_register_tab()

        self.bind("<Return>", self._on_enter_pressed)

        self._status = ctk.CTkLabel(self, text="")
        self._status.pack(padx=root_pad_x, pady=(0, 14))

    def _set_status(self, text: str):
        self._status.configure(text=text)

    def _build_login_tab(self):
        ctk.CTkLabel(
            self._login_tab,
            text="Login",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(18, 6))

        self._login_username = ctk.CTkEntry(self._login_tab, placeholder_text="Username")
        self._login_username.pack(fill="x", padx=16, pady=(6, 10))

        self._login_password = ctk.CTkEntry(self._login_tab, placeholder_text="Password", show="*")
        self._login_password.pack(fill="x", padx=16, pady=(0, 18))

        btn = ctk.CTkButton(
            self._login_tab,
            text="Login",
            command=self._on_login,
            height=44,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        btn.pack(fill="x", padx=16, pady=(0, 10))

    def _build_register_tab(self):
        ctk.CTkLabel(
            self._register_tab,
            text="Create account",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(18, 6))

        self._register_username = ctk.CTkEntry(self._register_tab, placeholder_text="Username")
        self._register_username.pack(fill="x", padx=16, pady=(6, 10))

        self._register_password = ctk.CTkEntry(self._register_tab, placeholder_text="Password", show="*")
        self._register_password.pack(fill="x", padx=16, pady=(0, 18))

        btn = ctk.CTkButton(
            self._register_tab,
            text="Register",
            command=self._on_register,
            height=36,
            fg_color="transparent",
            border_width=1,
        )
        btn.pack(fill="x", padx=16, pady=(0, 10))

    def _on_enter_pressed(self, _event):
        current = self._tabs.get()
        if current == "Login":
            self._on_login()
        elif current == "Register":
            self._on_register()

    def _on_login(self):
        username = self._login_username.get()
        password = self._login_password.get()
        res = self._db.login(username, password)
        self._set_status(res.message)

    def _on_register(self):
        username = self._register_username.get()
        password = self._register_password.get()
        res = self._db.register(username, password)
        self._set_status(res.message)
        if res.ok:
            self._register_password.delete(0, "end")


def main():
    db = AuthDB()
    app = LoginRegisterApp(db)
    app.mainloop()


if __name__ == "__main__":
    main()
