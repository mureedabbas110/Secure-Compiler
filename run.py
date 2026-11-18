"""One-click launcher: installs requirements, starts the server, opens the browser."""
import os
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)
URL = "http://127.0.0.1:5000"


def install():
    req = os.path.join(HERE, "requirements.txt")
    if os.path.exists(req):
        print("Checking dependencies...")
        subprocess.call([sys.executable, "-m", "pip", "install", "-q", "-r", req])


def open_when_ready():
    for _ in range(60):
        try:
            urllib.request.urlopen(URL, timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    webbrowser.open(URL)


def create_demo_user():
    from auth import init_db, User
    init_db()
    if User.register("admin", "admin123"):
        print("Demo account created -> username: admin | password: admin123")
    else:
        print("Demo account ready -> username: admin | password: admin123")


def check_project():
    missing = [d for d in ("compiler", "security", "templates") if not os.path.isdir(os.path.join(HERE, d))]
    if missing:
        print("\nERROR: these folders are missing next to run.py: " + ", ".join(missing))
        print("Copy your original 'compiler' and 'security' folders into this folder, then run again.")
        sys.exit(1)


if __name__ == "__main__":
    check_project()
    install()
    create_demo_user()
    threading.Thread(target=open_when_ready, daemon=True).start()
    try:
        from app import app
    except Exception:
        import traceback
        traceback.print_exc()
        print("\nERROR: app.py could not start. Read the error above (missing module or folder).")
        sys.exit(1)
    print(f"Secure Compiler running at {URL}  (press Ctrl+C to stop)")
    app.run(port=5000, debug=False, use_reloader=False, threaded=False)
