from flask import Flask, render_template, request, redirect, session, abort, flash, make_response,render_template_string,Response
from utils.db import get_db
from utils.modbus_client import read_device_registers, write_device_state, write_device_operator
from werkzeug.security import check_password_hash
import config
from weasyprint import HTML
import io
import subprocess
import sys
import os
import itertools
from datetime import datetime

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.debug = config.DEBUG


# --------------------
# LOGIN
# --------------------
@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        #VULNERABLE
        username.replace("'","\\'")
        password.replace("'","\\'")

        db = get_db()
        user = db.execute(
            f"""SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"""
        ).fetchone()

        if user:
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

    # ---- MODBUS WRITE ----
    write_device_state(device_id, 1)

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

    # ---- MODBUS WRITE ----
    write_device_state(device_id, 0)
    write_device_operator(device_id, 0)

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

    # Vulnerable , not-validated input
    css_url = request.args.get("css", "")
    
    compliance_url = request.args.get("compliance_url", "")
    external_content = ""

    if compliance_url:
        try:
            import requests 
            #SSRF
            r = requests.get(compliance_url, timeout=5)
            external_content = f"<div style='border:2px solid red; padding:10px'><h3>External Compliance Data:</h3>{r.text}</div>"
        except Exception as e:
            external_content = f"<p style='color:red'>Error fetching external data: {str(e)}</p>"

    db = get_db()
    logs = db.execute(
        "SELECT * FROM maintenance_logs ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()

    # HTML DEL REPORT
    html_content = f"""
    <html>
    <head>
        <title>Maintenance Report</title>

        <link rel="stylesheet" href="{css_url}">
    </head>
    <body>
        <h1>Maintenance Report</h1>

        {external_content}

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
    HTML(string=html_content, base_url='/').write_pdf(pdf_io)
    
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
            filepath = os.path.join("/tmp", file.filename)
            file.save(filepath)
            
            try:
                result = subprocess.check_output([sys.executable, filepath], stderr=subprocess.STDOUT)
                output = f"Script Output:\n\n{result.decode('utf-8')}"
            except subprocess.CalledProcessError as e:
                output = f"Execution Error:\n{e.output.decode('utf-8')}"
            except Exception as e:
                output = f"General Error: {str(e)}"

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
            
            is_safe, message = security_scanner(content)
            
            if not is_safe:
                return f"SECURITY ALERT: {message}"
            
            try:
                if key:
                    content = xor_decrypt(content, key)
                    output += "File decrypted successfully.\n"
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

    requested_file = request.args.get('file', default_filename)
    filepath_to_read = os.path.join(log_dir, requested_file)
    
    if os.path.exists(filepath_to_read):
        with open(filepath_to_read, "r", errors="ignore") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    else:
        return f"Error: Log file '{requested_file}' not found in {log_dir}.", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=False)