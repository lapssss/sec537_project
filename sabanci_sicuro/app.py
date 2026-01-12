from flask import Flask, render_template, request, redirect, session, abort, flash, make_response,render_template_string,Response
from utils.db import get_db
from utils.modbus_client import read_device_registers, write_device_state, write_device_operator
from werkzeug.security import check_password_hash
import config
from weasyprint import HTML
import io
from urllib.parse import urlparse
import subprocess
import sys
import os
import itertools
from datetime import datetime
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.debug = config.DEBUG
csrf = CSRFProtect(app)

ALLOWED_DOMAINS = ['example.com']

last_state_change = {}

def is_safe_url(target_url):
    try:
        parsed = urlparse(target_url)
        
        domain = parsed.netloc.lower().split(':')[0]
        if domain not in ALLOWED_DOMAINS:
            print(f"[DEBUG] BLOCCO: Dominio '{domain}' non è in {ALLOWED_DOMAINS}")
            return False
            
        print("[DEBUG] SUCCESS: URL approvato!")
        return True
    except Exception as e:
        print(f"[DEBUG] ERRORE Parsing: {e}")
        return False

# --------------------
# LOGIN
# --------------------
@app.route("/", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]

            db.execute(
                """
                INSERT INTO maintenance_logs
                VALUES (NULL, NULL, ?, 'LOGIN_SUCCESS', NULL, datetime('now'))
                """,
                (user["id"],)
            )
            db.commit()

            return redirect("/dashboard")

        error = "Invalid username or password"

        db.execute(
            """
            INSERT INTO maintenance_logs
            VALUES (NULL, NULL, NULL, 'LOGIN_FAILED', NULL, datetime('now'))
            """
        )
        db.commit()

    return render_template("login.html", error=error)

# --------------------
# LOGOUT
# --------------------
@app.route("/logout")
def logout():
    if "user_id" in session:
        db = get_db()
        db.execute(
            """
            INSERT INTO maintenance_logs 
            VALUES (NULL, NULL, ?, 'LOGOUT', NULL, datetime('now'))
            """,
            (session.get("user_id"),)
        )
        db.commit()

    session.clear()
    return redirect("/")


# --------------------
# DASHBOARD
# --------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    db_devices = db.execute("SELECT * FROM devices").fetchall()

    devices = []

    for d in db_devices:
        maintenance_state, operator_assigned = read_device_registers(d["id"])

        if maintenance_state is None:
            maintenance_state = 0
        if operator_assigned is None:
            operator_assigned = 0

        devices.append({
            "id": d["id"],
            "name": d["name"],
            "maintenance": maintenance_state,
            "assigned_technician": d["assigned_technician"] if operator_assigned else None
        })

    return render_template(
        "dashboard.html",
        devices=devices,
        role=session.get("role")
    )


# --------------------
# START MAINTENANCE
# --------------------
@app.route("/maintenance/start", methods=["POST"])
def start_maintenance():
    if "user_id" not in session or session.get("role") != "technician":
        abort(403)

    device_id = int(request.form["device_id"])
    db = get_db()

    device = db.execute(
        "SELECT id, maintenance FROM devices WHERE id = ?",
        (device_id,)
    ).fetchone()

    if not device:
        flash("Invalid device ID")
        return redirect("/dashboard")

    if device["maintenance"] == 1:
        flash("Device already in maintenance")
        return redirect("/dashboard")
    
    now = datetime.now()

    # --- PATCH 3.1: RATE LIMITING ---
    if device_id in last_state_change:
        delta = (now - last_state_change[device_id]).total_seconds()
        if delta < 10:  # 10 seconds limit
            db.execute(
                """
                INSERT INTO maintenance_logs
                VALUES (NULL, ?, ?, 'RATE_LIMITING_ATTACK', NULL, datetime('now'))
                """,
                (device_id,session["user_id"])
            )
            flash(f"SAFETY ALERT: Hardware protection active. Wait {10 - int(delta)}s.")
            return redirect("/dashboard")
    
    active_count = db.execute("SELECT COUNT(*) FROM devices WHERE maintenance = 0").fetchone()[0]
    total_count = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    #PATCH 3.2
    if (active_count - 1) < (total_count / 2):
        db.execute(
                """
                INSERT INTO maintenance_logs
                VALUES (NULL, NULL, ?, 'POSSIBLE_ATTACK', NULL, datetime('now'))
                """,
                (session["user_id"])
        )
        flash("OPERATIONAL WARNING: System operating below 50% capacity!")
        # Note: only a warning is throw, the action is still possible !

    # ---- MODBUS WRITE ----
    write_device_state(device_id, 1)
    last_state_change[device_id] = now

    db.execute(
        "UPDATE devices SET maintenance = 1 WHERE id = ?",
        (device_id,)
    )

    db.execute(
        """
        INSERT INTO maintenance_logs
        VALUES (NULL, ?, ?, 'START', NULL, datetime('now'))
        """,
        (device_id, session["user_id"])
    )
    db.commit()

    return redirect("/dashboard")


# --------------------
# ASSIGN TECHNICIAN
# --------------------
@app.route("/maintenance/assign", methods=["POST"])
def assign_technician():
    if "user_id" not in session or session.get("role") != "technician":
        abort(403)

    device_id = int(request.form["device_id"])
    tech_id = request.form["technician"]
    db = get_db()

    device = db.execute(
        "SELECT id, maintenance FROM devices WHERE id = ?",
        (device_id,)
    ).fetchone()

    technician = db.execute(
        "SELECT username FROM users WHERE id = ?",
        (tech_id,)
    ).fetchone()

    if not device or not technician:
        flash("Invalid device or technician ID")
        return redirect("/dashboard")

    if device["maintenance"] == 0:
        flash("Device is not in maintenance")
        return redirect("/dashboard")

    # ---- MODBUS WRITE ----
    write_device_operator(device_id, 1)

    db.execute(
        """
        UPDATE devices
        SET assigned_technician = ?
        WHERE id = ?
        """,
        (technician["username"], device_id)
    )

    db.execute(
        """
        INSERT INTO maintenance_logs
        VALUES (NULL, ?, ?, 'ASSIGN', ?, datetime('now'))
        """,
        (device_id, session["user_id"], technician["username"])
    )

    db.commit()
    return redirect("/dashboard")


# --------------------
# STOP MAINTENANCE
# --------------------
@app.route("/maintenance/stop", methods=["POST"])
def stop_maintenance():
    if "user_id" not in session or session.get("role") != "technician":
        abort(403)

    device_id = int(request.form["device_id"])
    db = get_db()

    device = db.execute(
        "SELECT id, maintenance FROM devices WHERE id = ?",
        (device_id,)
    ).fetchone()

    if not device:
        flash("Invalid device ID")
        return redirect("/dashboard")

    if device["maintenance"] == 0:
        flash("Device is not in maintenance")
        return redirect("/dashboard")
    
    now = datetime.now()

    # --- PATCH 3.1: RATE LIMITING ---
    if device_id in last_state_change:
        delta = (now - last_state_change[device_id]).total_seconds()
        if delta < 10:  # 10 seconds limit
            db.execute(
                """
                INSERT INTO maintenance_logs
                VALUES (NULL, ?, ?, 'RATE_LIMITING_ATTACK', NULL, datetime('now'))
                """,
                (device_id,session["user_id"])
            )
            flash(f"SAFETY ALERT: Hardware protection active. Wait {10 - int(delta)}s.")
            return redirect("/dashboard")

    # ---- MODBUS WRITE ----
    write_device_state(device_id, 0)
    write_device_operator(device_id, 0)

    last_state_change[device_id] = now

    db.execute(
        """
        UPDATE devices
        SET maintenance = 0, assigned_technician = NULL
        WHERE id = ?
        """,
        (device_id,)
    )

    db.execute(
        """
        INSERT INTO maintenance_logs
        VALUES (NULL, ?, ?, 'STOP', NULL, datetime('now'))
        """,
        (device_id, session["user_id"])
    )

    db.commit()
    return redirect("/dashboard")

@app.route("/report/pdf")
def generate_pdf_report():
    if "user_id" not in session:
        abort(403)

    #(PATCH 2.1)
    css_input = request.args.get("css", "")
    if css_input:
        try:
            parsed = urlparse(css_input)
            # Check protocollo
            if parsed.scheme not in ['http', 'https']:
                db.execute(
                    """
                    INSERT INTO maintenance_logs
                    VALUES (NULL, NULL, ?, 'SSRF', NULL, datetime('now'))
                    """,
                    (session["user_id"])
                )
                return "SECURITY ERROR: Only HTTP/HTTPS allowed for CSS.", 400
            
            # Check dominio (Allowlist per CSS)
            domain = parsed.netloc.lower().split(':')[0]
            ALLOWED_CSS_DOMAIN = 'cdn.jsdelivr.net'
            if domain != ALLOWED_CSS_DOMAIN:
                db.execute(
                    """
                    INSERT INTO maintenance_logs
                    VALUES (NULL, NULL, ?, 'SSRF', NULL, datetime('now'))
                    """,
                    (session["user_id"])
                )
                return f"SECURITY ERROR: Domain '{domain}' not trusted for CSS.", 403
        except:
            return "Invalid CSS URL", 400
    
    #(PATCH 2.2 - SSRF
    target_url = request.args.get("compliance_url", "") 
    compliance_data = "No external data requested."

    if target_url:
        import requests
        if is_safe_url(target_url):
            try:
                r = requests.get(target_url, timeout=5)
                compliance_data = f"External Compliance Data:\n{r.text[:500]}"
            except Exception as e:
                compliance_data = f"Error fetching data: {str(e)}"
        else:
            db.execute(
                """
                INSERT INTO maintenance_logs
                VALUES (NULL, NULL, ?, 'SSRF', NULL, datetime('now'))
                """,
                (session["user_id"])
            )
            compliance_data = "SECURITY ERROR: URL blocked by security policy (Allowlist)."
            
    db = get_db()
    logs = db.execute("SELECT * FROM maintenance_logs ORDER BY timestamp DESC LIMIT 20").fetchall()

    html_content = f"""
    <html>
    <head>
        <title>Maintenance Report</title>
        <link rel="stylesheet" href="{css_input}">
        
        <style>
            .compliance-box {{
                border: 2px solid red;
                padding: 10px;
                margin: 10px 0;
                background-color: #f9f9f9;
                font-family: monospace;
                white-space: pre-wrap; 
            }}
        </style>
    </head>
    <body>
        <h1>Maintenance Report</h1>

        <div class="compliance-box">
            <h3>Compliance Status</h3>
            {compliance_data}
        </div>

        <table border="1">
            <tr>
                <th>Device</th>
                <th>User</th>
                <th>Action</th>
                <th>Timestamp</th>
            </tr>
    """

    for log in logs:
        html_content += f"""
        <tr>
            <td>{log['device_id']}</td>
            <td>{log['user_id']}</td>
            <td>{log['action']}</td>
            <td>{log['timestamp']}</td>
        </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    pdf_io = io.BytesIO()
    HTML(string=html_content).write_pdf(pdf_io)

    response = make_response(pdf_io.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "inline; filename=scada_report.pdf"

    return response

@app.route("/maintenance/script", methods=["GET", "POST"])
def maintenance():
    if "user_id" not in session or session.get("role") != "technician":
        abort(403)
    
    output = ""
    
    if request.method == "POST":
        if 'file' not in request.files:
            return "No file part"
            
        file = request.files['file']
        
        if file.filename == '':
            return "No selected file"

        if file:
            # We save the file to /tmp
            filepath = os.path.join("/tmp", file.filename)
            file.save(filepath)
            
            # ---------------------------------------------------------
            # VULNERABILITY PATCHED
            # ---------------------------------------------------------
            # We REMOVED the automatic execution logic.
            # Now we simply acknowledge the upload.
            # The malicious code is on disk, but it is never executed.
            # ---------------------------------------------------------
            
            output = f"SUCCESS: The file '{file.filename}' has been uploaded to the server storage.\n" \
                    f"Automatic execution has been DISABLED for security reasons.\n" \
                    f"A technician will review the script code manually."

    return render_template_string("""
        <h1>SCADA Maintenance Console</h1>
        <p>Upload a Python diagnostic script (.py) to check sensor status.</p>
        <hr>
        <form method="post" enctype="multipart/form-data">
            <label>Select Diagnostic Script:</label>
            <input type="file" name="file">
            <input type="submit" value="Upload and Execute">
        </form>
        <br>
        <h3>System Output:</h3>
        <pre style="background: #eee; padding: 10px; border: 1px solid #999;">{{ output }}</pre>
        <hr>
        <a href="/dashboard">Back to Dashboard</a>
    """, output=output)

#Simulated Antivirus
def security_scanner(content_bytes):
    signatures = [b"import os", b"import socket", b"subprocess", b"popen"]
    for sig in signatures:
        if sig in content_bytes:
            return False, f"Malware detected! Signature found: {sig.decode()}"
    return True, "Scan Passed"

def xor_decrypt(data, key):
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

@app.route("/maintenance/secure_upload", methods=["GET", "POST"])
def secure_upload():
    if "user_id" not in session or session.get("role") != "technician":
        abort(403)

    output = ""
    
    if request.method == "POST":
        file = request.files.get('file')
        key = request.form.get('key')

        if file:
            content = file.read()
            
            try:
                if key:
                    content = xor_decrypt(content, key)
                    output += "File decrypted successfully.\n"
                #PATCHED SCANNING AFTER DECRYPTION
                is_safe, message = security_scanner(content)
                if not is_safe:
                    db.execute(
                        """
                        INSERT INTO maintenance_logs
                        VALUES (NULL, NULL, ?, 'CWE-434-Encrypted', NULL, datetime('now'))
                        """,
                        (session["user_id"])
                    )
                    return f"SECURITY ALERT: {message}"
                temp_path = "/tmp/payload.py"
                with open(temp_path, "wb") as f:
                    f.write(content)
                result = subprocess.check_output([sys.executable, temp_path], stderr=subprocess.STDOUT)
                output += f"Execution Result:\n{result.decode('utf-8')}"
                
            except Exception as e:
                output += f"Error: {str(e)}"
                
    return render_template_string("""
        <h1>Secure Firmware Updater</h1>
        <p>This uploader is protected by an antivirus.</p>
        <p>If you are uploading an encrypted patch, provide the decryption key.</p>
        <hr>
        <form method="post" enctype="multipart/form-data">
            <label>Firmware Patch:</label> <input type="file" name="file"><br><br>
            <label>Decryption Key (optional):</label> <input type="text" name="key"><br><br>
            <input type="submit" value="Scan & Install">
        </form>
        <pre>{{ output }}</pre>
    """, output=output)

@app.route("/logs/raw", methods=["GET"])
def raw_logs():
    
    db = get_db()
    logs = db.execute(
        "SELECT * FROM maintenance_logs ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    log_dir = "/var/log"
    default_filename = "maintenance_export.log"
    export_filepath = os.path.join(log_dir, default_filename)

    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        with open(export_filepath, "w") as f:
            f.write("--- SCADA SYSTEM RAW LOGS (Real-Time Export) ---\n")
            f.write(f"Export Time: {datetime.now()}\n")
            f.write("-" * 60 + "\n")
            f.write(f"{'DEVICE':<10} | {'USER':<8} | {'ACTION':<10} | {'TIMESTAMP'}\n")
            f.write("-" * 60 + "\n")
            
            for row in logs:
                r = dict(row)
                
                dev = str(r.get('device_id') or '-')
                usr = str(r.get('user_id') or '-')
                act = str(r.get('action') or '-')
                time = str(r.get('timestamp') or '-')

                f.write(f"{dev:<10} | {usr:<8} | {act:<10} | {time}\n")
                
    except Exception as e:
        print(f"Errore scrittura export: {e}",flush=True)
    
    #PATCH
    
    requested_file = request.args.get('file', default_filename)
    
    base_dir = os.path.abspath(log_dir)
    
    unsafe_path = os.path.join(base_dir, requested_file)
    
    real_path = os.path.abspath(unsafe_path)
    
    if os.path.commonprefix([base_dir, real_path]) != base_dir:
        db.execute(
            """
            INSERT INTO maintenance_logs
            VALUES (NULL, NULL, ?, 'PATH_TRAVERSAL', NULL, datetime('now'))
            """,
            (session["user_id"])
        )
        print(f"!!! SECURITY ALERT !!! Tentativo di Path Traversal bloccato: {requested_file}", flush=True)
        return "Access Denied: Invalid file path.", 403

    if os.path.exists(real_path):
        with open(real_path, "r", errors="ignore") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    else:
        return f"Error: Log file not found.", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=False)