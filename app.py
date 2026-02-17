from flask import Flask, request, render_template
import requests
import time

app = Flask(__name__)

API_KEY = "aa1cabdc4f4c55f6b981e3efcab092f72bd40bc440e69cafb41f928981477542"
VT_HEADERS = {"x-apikey": API_KEY}

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        url_to_check = request.form["url"]

        try:
            # 1️⃣ إرسال الرابط لفحصه في VirusTotal
            post_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=VT_HEADERS,
                data={"url": url_to_check}
            ).json()

            analysis_id = post_response.get("data", {}).get("id")

            if not analysis_id:
                result = "❌ لم يتمكن من إنشاء التحليل"
            else:
                # 2️⃣ انتظار ثانيتين ثم طلب نتيجة التحليل النهائي
                time.sleep(2)
                analysis_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=VT_HEADERS
                ).json()

                stats = analysis_response.get("data", {}).get("attributes", {}).get("stats", {})

                if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                    result = "🚨 الموقع خطر!"
                elif stats.get("harmless", 0) > 0:
                    result = "✅ الموقع آمن"
                else:
                    result = "❌ لم يتمكن من تحديد حالة الموقع"

        except Exception as e:
            print(e)
            result = "❌ حدث خطأ أثناء الفحص"

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
