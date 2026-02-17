from flask import Flask, request, render_template, jsonify
import requests
import base64

app = Flask(__name__)

API_KEY = "aa1cabdc4f4c55f6b981e3efcab092f72bd40bc440e69cafb41f928981477542"
VT_HEADERS = {"x-apikey": API_KEY}

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/check_url", methods=["POST"])
def check_url():
    url_to_check = request.form.get("url", "")
    if not url_to_check:
        return jsonify({"result": "❌ يرجى إدخال رابط"}), 400

    try:
        # ترميز الرابط لـ Base64 URL-safe
        url_bytes = url_to_check.encode("utf-8")
        url_b64 = base64.urlsafe_b64encode(url_bytes).decode().strip("=")

        # طلب تحليل الرابط
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_b64}",
            headers=VT_HEADERS
        ).json()

        stats = analysis_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            result = "🚨 الموقع خطر!"
        elif stats.get("harmless", 0) > 0:
            result = "✅ الموقع آمن"
        else:
            result = "❌ لم يتمكن من تحديد حالة الموقع"

        return jsonify({"result": result})

    except Exception as e:
        print(e)
        return jsonify({"result": "❌ حدث خطأ أثناء الفحص"}), 500

if __name__ == "__main__":
    app.run(debug=True)
