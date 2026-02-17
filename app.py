from flask import Flask, request, render_template
import requests

app = Flask(__name__)

API_KEY = "aa1cabdc4f4c55f6b981e3efcab092f72bd40bc440e69cafb41f928981477542"  # ضع هنا مفتاح VirusTotal الخاص بك

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        url_to_check = request.form["url"]

        # إرسال الرابط لفحصه في VirusTotal
        try:
            url_id_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": API_KEY},
                data={"url": url_to_check}
            ).json()

            analysis_id = url_id_response.get("data", {}).get("id")
            if analysis_id:
                analysis_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": API_KEY}
                ).json()

                stats = analysis_response.get("data", {}).get("attributes", {}).get("stats", {})
                if stats.get("malicious", 0) > 0:
                    result = "🚨 الموقع خطر!"
                else:
                    result = "✅ الموقع آمن"
            else:
                result = "❌ لم يتمكن من فحص الرابط"
        except:
            result = "❌ حدث خطأ أثناء الفحص"
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
