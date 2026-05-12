from flask import Flask, request, jsonify, render_template
import os
from parser import parse_pcap, detect_anomalies, get_timeline

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files["file"]
    
    if not file.filename.endswith(".pcap"):
        return jsonify({"error": "Only .pcap files allowed"}), 400
    
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    result = parse_pcap(filepath)
    result["anomalies"] = detect_anomalies(filepath)
    result["timeline"] = get_timeline(filepath)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)