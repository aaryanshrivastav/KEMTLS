from flask import Flask, jsonify
import threading
import time

app = Flask(__name__)

DEMO_EVENTS = []
DEMO_RUNNING = False


def add_event(phase, title, details):
    DEMO_EVENTS.append({
        "phase": phase,
        "title": title,
        "details": details
    })


def run_demo_flow():
    global DEMO_RUNNING
    DEMO_RUNNING = True
    DEMO_EVENTS.clear()

    # Phase 1: KEMTLS
    time.sleep(0.5)
    add_event(
        "KEMTLS",
        "Secure Channel Established",
        {
            "Transport": "KEMTLS",
            "KEM": "Kyber768",
            "Forward Secrecy": "Yes",
            "Latency (ms)": 1.52
        }
    )

    # Phase 2: OIDC Token
    time.sleep(0.5)
    add_event(
        "OIDC",
        "ID Token Issued",
        {
            "Format": "JWT",
            "Signature": "Dilithium3",
            "PoP Binding": "Included",
            "Token Size (KB)": 7.5,
            "Latency (ms)": 0.55
        }
    )

    # Phase 3: PoP
    time.sleep(0.5)
    add_event(
        "PoP",
        "Proof of Possession Verified",
        {
            "Challenge–Response": "Success",
            "Replay Protection": "Enforced",
            "Verification Time (ms)": 0.15
        }
    )

    # Phase 4: Resource Access
    time.sleep(0.5)
    add_event(
        "Resource",
        "Protected Resource Access Granted",
        {
            "User": "alice",
            "Scope": "openid profile email",
            "Latency (ms)": 0.20
        }
    )

    DEMO_RUNNING = False


@app.route("/demo/start", methods=["POST"])
def start_demo():
    global DEMO_RUNNING
    if not DEMO_RUNNING:
        threading.Thread(target=run_demo_flow).start()
    return jsonify({"status": "started"})


@app.route("/demo/events", methods=["GET"])
def get_events():
    return jsonify({
        "running": DEMO_RUNNING,
        "events": DEMO_EVENTS
    })


if __name__ == "__main__":
    app.run(port=7000, debug=True)
