import os
import json
import pandas as pd
import requests
from flask import Flask, request, render_template, jsonify
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
import google.generativeai as genai
from dotenv import load_dotenv

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

import predefined_model as pm

load_dotenv()

app = Flask(__name__, template_folder="templates")

# API
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_WHATSAPP_NUMBER = 'whatsapp:+14155238886'
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
try:
    genai.configure(api_key=GEMINI_API_KEY)
except Exception as e:
    print(f"Error configuring Gemini: {e}")

SCAM_REPORTS_FILE = 'scam_reports.json'
USER_STATS_FILE = 'user_stats.json'
CONFIDENCE_THRESHOLD = 0.80

user_state = {}


def load_json_file(filename, default_value):
    """Safely loads a JSON file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default_value

def save_json_file(filename, data):
    """Safely saves data to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def save_scam_report(message):
    """Adds a new scam report to the file, avoiding duplicates."""
    reports = load_json_file(SCAM_REPORTS_FILE, [])
    if message not in reports:
        reports.append(message)
        save_json_file(SCAM_REPORTS_FILE, reports)
        return True
    return False


#AI
def analyze_text_with_gemini(user_content):
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = (
            "You are a cybersecurity expert 'Digital Kavalan'. "
            "Analyze the following WhatsApp message for scams. "
            "Provide a clear verdict: 'SAFE ✅', 'SUSPICIOUS ⚠️', or 'DANGEROUS ❌'. "
            "Then, provide a 'Tamil Explanation:' and an 'English Translation:'.\n\n"
            f"Message to analyze:\n---\n{user_content}\n---"
        )
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error during Gemini Text API call: {e}")
        return "Sorry, I'm having trouble analyzing this text with our advanced model."


def analyze_image_with_gemini(image_url):
    """Analyzes an image from a URL (for WhatsApp)."""
    try:
        image_response = requests.get(
            image_url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=10
        )
        if image_response.status_code != 200:
            return "Sorry, I couldn't download the image to analyze it."
        image_data = {
            'mime_type': image_response.headers['Content-Type'],
            'data': image_response.content
        }
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = (
            "You are a strict safety analyst 'Digital Kavalan'. "
            "Analyze the image for scams, phishing, or harmful content. "
            "Provide a verdict: 'SAFE ✅', 'SUSPICIOUS ⚠️', or 'DANGEROUS ❌', "
            "followed by 'Tamil Explanation:' and 'English Translation:'."
        )
        response = model.generate_content([prompt, image_data])
        return response.text
    except Exception as e:
        print(f"Error during Gemini Image URL API call: {e}")
        return "Sorry, I'm having trouble analyzing this image."

def analyze_image_data_with_gemini(image_file):
    """Analyzes image data from a direct file upload (for Web)."""
    try:
        image_data = {
            'mime_type': image_file.mimetype,
            'data': image_file.read()
        }
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = (
            "You are a strict safety analyst 'Digital Kavalan'. "
            "Analyze the image for scams, phishing attempts, or harmful content. "
            "Provide a verdict: 'SAFE ✅', 'SUSPICIOUS ⚠️', or 'DANGEROUS ❌', "
            "followed by 'Tamil Explanation:' and 'English Translation:'."
        )
        response = model.generate_content([prompt, image_data])
        is_scam = "DANGEROUS" in response.text or "SUSPICIOUS" in response.text
        return response.text, is_scam
    except Exception as e:
        print(f"Error during Gemini Image Data API call: {e}")
        return "Sorry, I'm having trouble analyzing this image.", True


def get_trained_model():
    """Builds and trains a model using the LATEST data from the scam reports file."""
    safe_messages = [ "Hello, how are you?", "See you tomorrow at 5pm.", "Okay, thank you!" ]
    safe_df = pd.DataFrame({'text': safe_messages, 'label': [0] * len(safe_messages)})
    scam_reports = load_json_file(SCAM_REPORTS_FILE, [])
    if scam_reports:
        scam_df = pd.DataFrame(scam_reports, columns=['text'])
        scam_df['label'] = 1
        training_df = pd.concat([safe_df, scam_df], ignore_index=True)
    else:
        training_df = safe_df
    model_pipeline = make_pipeline(TfidfVectorizer(), MultinomialNB())
    if not training_df.empty and len(training_df['label'].unique()) > 1:
        model_pipeline.fit(training_df['text'], training_df['label'])
        return model_pipeline
    return None


def analyze_message(msg):
    """Comprehensive analysis for the WhatsApp Bot."""
    is_scam_detected = False
    if pm.check_for_safe_keywords(msg):
        return "Verdict: SAFE ✅\n\n(Contains common safe keywords)", is_scam_detected
    is_suspicious_url, url_found = pm.check_for_suspicious_urls(msg)
    if is_suspicious_url:
        return f"Verdict: DANGEROUS ❌\nSuspicious link found.", True
    is_scam_keyword, keyword_found = pm.check_for_scam_keywords(msg)
    if is_scam_keyword:
        return f"Verdict: SUSPICIOUS ⚠️\nKeyword '{keyword_found}' found.", True
    scam_database = load_json_file(SCAM_REPORTS_FILE, [])
    if msg in scam_database:
        return "Verdict: DANGEROUS ❌ (Known scam)", True
    text_model = get_trained_model()
    if text_model:
        confidence = max(text_model.predict_proba([msg])[0])
        if confidence >= CONFIDENCE_THRESHOLD:
            prediction = text_model.predict([msg])[0]
            if prediction == 1:
                return f"Verdict: DANGEROUS ❌ (Model is {confidence:.0%} confident)", True
            else:
                return f"Verdict: SAFE ✅ (Model is {confidence:.0%} confident)", False
    gemini_result = analyze_text_with_gemini(msg)
    if any(w in gemini_result for w in ["SCAM", "DANGEROUS", "SUSPICIOUS"]):
        is_scam_detected = True
    return gemini_result, is_scam_detected


def analyze_message_for_web(msg):
    """Simplified checker for the website."""
    if pm.check_for_safe_keywords(msg):
        return "Verdict: SAFE ✅\n\n(Common safe phrase.)", False
    is_suspicious_url, url_found = pm.check_for_suspicious_urls(msg)
    if is_suspicious_url:
        return f"Verdict: DANGEROUS ❌\nContains a suspicious link: `{url_found}`", True
    is_scam_keyword, keyword_found = pm.check_for_scam_keywords(msg)
    if is_scam_keyword:
        return f"Verdict: SUSPICIOUS ⚠️\nKeyword '{keyword_found}' is often used in scams.", True
    scam_database = load_json_file(SCAM_REPORTS_FILE, [])
    if msg in scam_database:
        return "Verdict: DANGEROUS ❌\n\n(This is a known scam reported by other users.)", True
    return "Verdict: LIKELY SAFE ✅\n\n(No obvious signs of a scam found.)", False


@app.route('/webhook', methods=['POST'])
def webhook():
    incoming_msg = request.values.get('Body', '').strip()
    from_number = request.values.get('From', '')
    media_url = request.values.get('MediaUrl0')
    response = MessagingResponse()
    user_stats = load_json_file(USER_STATS_FILE, {})
    if from_number not in user_stats:
        user_stats[from_number] = {"checked": 0, "scams_found": 0}
    if user_state.get(from_number) == 'reporting_scam':
        if save_scam_report(incoming_msg):
            response.message("Thank you! 🙏 Your report helps protect others.")
        else:
            response.message("Thank you, but this has already been reported. 👍")
        user_state.pop(from_number, None)
        return str(response)
    if media_url:
        user_stats[from_number]['checked'] += 1
        analysis_result = analyze_image_with_gemini(media_url)
        if "DANGEROUS" in analysis_result:
            user_stats[from_number]['scams_found'] += 1
        save_json_file(USER_STATS_FILE, user_stats)
        response.message(analysis_result)
        return str(response)
    if incoming_msg.lower() in ['hi', 'hello', 'menu']:
        welcome_text = (
            "Vanakkam! 🙏 I am *Digital Kavalan*.\n\n"
            "Please reply with a number:\n"
            "*1.* 📝 Check a Message/Image\n*2.* 🚩 Report a New Scam\n*3.* 📈 My Safety Dashboard"
        )
        response.message(welcome_text)
    elif incoming_msg == '1':
        response.message("Okay! Please send the suspicious message or image.")
    elif incoming_msg == '2':
        response.message("Thank you! Please send the scam message to report it.")
        user_state[from_number] = 'reporting_scam'
    elif incoming_msg == '3':
        stats = user_stats[from_number]
        dashboard_text = (
            f"📈 *Your Dashboard*\n\n"
            f"Checked: {stats['checked']}\nScams Detected: {stats['scams_found']}"
        )
        response.message(dashboard_text)
    else:
        user_stats[from_number]['checked'] += 1
        result, is_scam = analyze_message(incoming_msg)
        if is_scam:
            user_stats[from_number]['scams_found'] += 1
        response.message(result)
        save_json_file(USER_STATS_FILE, user_stats)
    return str(response)


@app.route('/')
def home():
    return render_template("index.html")

@app.route('/api/check', methods=['POST'])
def api_check():
    user_id = request.form.get("user_id", "web_user")
    user_stats = load_json_file(USER_STATS_FILE, {})
    if user_id not in user_stats:
        user_stats[user_id] = {"checked": 0, "scams_found": 0}
    user_stats[user_id]["checked"] += 1
    
    result = "No valid input received."
    is_scam = False

    if 'image' in request.files and request.files['image'].filename != '':
        image_file = request.files['image']
        result, is_scam = analyze_image_data_with_gemini(image_file)
    else:
        msg = request.form.get("message", "")
        if msg:
            result, is_scam = analyze_message_for_web(msg)

    if is_scam:
        user_stats[user_id]["scams_found"] += 1
    
    save_json_file(USER_STATS_FILE, user_stats)
    return jsonify({"result": result.replace('\n', '<br>')})


@app.route('/api/report', methods=['POST'])
def api_report():
    data = request.json
    scam_msg = data.get("message", "")
    if save_scam_report(scam_msg):
        result_msg = "✅ Scam reported successfully & database updated."
    else:
        result_msg = "ℹ️ This scam has already been reported. Thank you!"
    return jsonify({"result": result_msg})


@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    user_id = request.args.get("user_id", "web_user")
    user_stats = load_json_file(USER_STATS_FILE, {})
    stats = user_stats.get(user_id, {"checked": 0, "scams_found": 0})
    return jsonify(stats)


if __name__ == '__main__':
    app.run(port=5000, debug=True)