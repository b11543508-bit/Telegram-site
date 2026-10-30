from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def home():
    return "Telegram Login Server is running!"

@app.route("/auth/telegram", methods=["POST"])
def telegram_auth():
    return jsonify({
        "status": "error",
        "message": "Telegram signature verification is not configured"
    }), 501
