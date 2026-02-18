from flask import Flask, request, render_template
import requests
import base64

app = Flask(__name__)

# ضع مفتاح VirusTotal الخاص بك هنا
API_KEY = "aa1cabdc4f4c55f6b981e3efcab092f72bd40bc440e69cafb41f928981477542"

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        url_to_check = request.form["url"]

        try:
            # ترميز الرابط لفحصه في VirusTotal
            url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": API_KEY},
                timeout=15
            )
            data = analysis_response.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            if stats.get("malicious", 0) > 0:
                result = "🚨 الموقع خطر!"
            else:
                result = "✅ الموقع آمن"
        except:
            result = "❌ حدث خطأ أثناء الفحص أو الرابط غير صالح"

    return render_template("index.html", result=result)
