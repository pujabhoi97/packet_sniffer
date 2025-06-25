from flask import Flask, render_template, jsonify
from sniffer import captured_data, lock, start_sniffing
import threading

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/data')
def get_data():
    with lock:
        return jsonify({
            "counts": {
                "tcp": captured_data["tcp"],
                "http": captured_data["http"],
                "dns": captured_data["dns"]
            },
            "http_hosts": captured_data["http_hosts"],
            "dns_queries": captured_data["dns_queries"],
            "tcp_sources": captured_data["tcp_sources"]
        })

if __name__ == '__main__':
    # Start sniffing in background
    sniffing_thread = threading.Thread(target=start_sniffing)
    sniffing_thread.daemon = True
    sniffing_thread.start()

    print("[*] Flask server starting...")
    app.run(debug=True)
