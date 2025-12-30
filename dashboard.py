from flask import Flask, jsonify, render_template_string
import json
import os

app = Flask(__name__)
DASHBOARD_FILE = "latest_alert.json"

# HTML Template (The UI)
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>cClear Live SOC Dashboard</title>
    <style>
        body { font-family: 'Courier New', monospace; background-color: #0d0d0d; color: #00ff00; text-align: center; padding: 50px; }
        .box { border: 2px solid #00ff00; padding: 20px; margin: 20px auto; width: 60%; border-radius: 10px; }
        h1 { font-size: 3em; }
        .critical { color: red; border-color: red; animation: blink 1s infinite; }
        .safe { color: #00ff00; border-color: #00ff00; }
        @keyframes blink { 50% { opacity: 0.5; } }
        #action-box { background-color: #222; color: #fff; padding: 10px; font-weight: bold; }
    </style>
    <script>
        function updateDashboard() {
            fetch('/data')
                .then(response => response.json())
                .then(data => {
                    const statusBox = document.getElementById('status-box');
                    const title = document.getElementById('status-title');
                    
                    if (data.severity === "CRITICAL" || data.severity === "HIGH") {
                        statusBox.className = "box critical";
                        title.innerText = "⚠️ ATTACK DETECTED ⚠️";
                        // document.getElementById('alert-sound').play();
                    } else {
                        statusBox.className = "box safe";
                        title.innerText = "SYSTEM SECURE";
                    }

                    document.getElementById('summary').innerText = data.summary;
                    document.getElementById('ip').innerText = "Source: " + (data.ip || "N/A");
                    document.getElementById('action').innerText = data.action;
                });
        }
        setInterval(updateDashboard, 2000); // Check for attacks every 2 seconds
    </script>
</head>
<body>
    <h1>🛡️ cClear Intelligence Center</h1>
    
    <div id="status-box" class="box safe">
        <h2 id="status-title">SYSTEM SECURE</h2>
        <h3 id="ip">Source: N/A</h3>
        <p id="summary">Waiting for telemetry...</p>
    </div>

    <div class="box">
        <h3>RECOMMENDED AI ACTION:</h3>
        <div id="action-box"><span id="action">Monitoring...</span></div>
    </div>
    
    
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_PAGE)

@app.route('/data')
def get_data():
    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, 'r') as f:
            return jsonify(json.load(f))
    return jsonify({"severity": "SAFE"})

if __name__ == '__main__':
    print("--- Web Dashboard Running on http://127.0.0.1:5000 ---")
    app.run(host='0.0.0.0', port=5000)