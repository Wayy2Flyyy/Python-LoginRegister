Simple Login & Register System (Python)

I built this project to create a clean, local login and registration system using Python. It’s designed as a front page for desktop applications, allowing users to register, log in securely, and access a main screen after authentication.

The goal was simplicity, security, and a solid foundation that can be expanded into larger projects.

Features

User registration and login

Secure password hashing (no plain-text passwords)

Local SQLite database (auto-created)

Clean, modern desktop UI

Front page displayed after successful login

Logout support

Tech Stack

Python 3.9+

CustomTkinter (UI)

SQLite (local database)

PBKDF2 password hashing

Installation

Install the required dependency:

pip install customtkinter

How It Works

When the app starts, users can either log in or create a new account. Credentials are stored securely in a local SQLite database. Once logged in, the user is taken to a simple front page where additional tools or features can be added.

Run the app:

python app.py

Why I Made This

I wanted a lightweight authentication system that works offline, doesn’t rely on web frameworks, and can be reused as the front page for desktop tools like calculators, stopwatches, or utilities.

Future Improvements

Remember-me option

Password reset flow

User roles (admin / user)

Dashboard cards for tools

Export as a standalone .exe