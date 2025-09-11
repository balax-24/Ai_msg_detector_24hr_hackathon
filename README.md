# Digital Kavalan 🛡️ — AI-Powered Scam Detection

**Digital Kavalan (டிஜிட்டல் காவலன் - Digital Guardian)** is a multi-platform scam detection application designed to protect users in India and beyond from online threats. It analyzes text and images for potential scams using a powerful, multi-layered approach and is accessible via a clean web interface and an integrated WhatsApp chatbot.

---

## ✨ Key Features

- 🌐 **Modern Web Interface**: A user-friendly front end for analyzing messages, uploading images for review, reporting new scams, and viewing a personalized safety dashboard.

- 📱 **Integrated WhatsApp Bot**: Analyze suspicious messages and images on the go, directly within WhatsApp, with simple menu-driven commands.

- 🧠 **Multi-Layered Analysis Engine**: The system uses a hybrid approach for maximum accuracy:
  1. **Rule-Based Filtering**: Instantly checks against predefined lists of scam keywords, common safe phrases, and suspicious URL domains.
  2. **Community-Sourced Database**: Leverages a dynamic `scam_reports.json` file, checking submissions against all user-reported scams.
  3. **Machine Learning Model**: A custom-trained Naive Bayes classifier provides a fast probability score for text-based threats.
  4. **Advanced AI with Google Gemini**: Utilizes Google's Gemini 1.5 Flash model for nuanced analysis of complex text and images that other layers might miss.

- 🖼️ **AI-Powered Image Analysis**: Leverages Gemini's vision capabilities to detect scams, phishing attempts, or harmful content within images sent via both the web and WhatsApp.

- 📊 **Personal Safety Dashboard**: Tracks user-specific statistics for the number of items checked and potential scams detected on their device.

---

## 🚀 Live Demo

Here’s a look at the Digital Kavalan web interface in action. The UI is designed to be simple, intuitive, and fast.

> *(Replace this text with a real screenshot of your application! You can drag and drop an image into the GitHub editor.)*

---

## 🛠️ Tech Stack

- **Backend**: Python, Flask, Scikit-learn, Pandas  
- **Frontend**: HTML5, Tailwind CSS, JavaScript  
- **APIs & Services**: Google Gemini API, Twilio WhatsApp API  

---

## ⚙️ Setup and Installation

Follow these steps to get the project running on your local machine.

### 1. Prerequisites

Make sure you have Python 3.8+ installed on your system.

---

### 2. Clone the Repository

```bash
git clone https://github.com/your-username/digital-kavalan.git
cd digital-kavalan
```

> Replace `your-username` with your actual GitHub username.

---

### 3. Create a Virtual Environment

It's highly recommended to use a virtual environment to manage project dependencies.

#### On macOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

#### On Windows:

```bash
python -m venv venv
.\venv\Scripts\activate
```

---

### 4. Install Dependencies

```bash
pip install flask pandas scikit-learn requests twilio google-generativeai python-dotenv
```

---

### 5. Configure Environment Variables

Create a file named `.env` in the root of your project folder and add your secret keys.

```env
# .env file
GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
TWILIO_ACCOUNT_SID="YOUR_TWILIO_ACCOUNT_SID"
TWILIO_AUTH_TOKEN="YOUR_TWILIO_AUTH_TOKEN"
```

> ⚠️ **Note**: Do not commit your `.env` file to Git for security reasons.

---

## ▶️ How to Run

### 1. Start the Flask Server

```bash
python bot_backend.py
```

The server will start, typically on:

```
http://127.0.0.1:5000
```

---

### 2. Access the Web Interface

Open your web browser and navigate to:

```
http://127.0.0.1:5000
```

Use the web interface to check messages, upload images, and report scams.

---

### 3. (Optional) Connect the WhatsApp Bot

To connect the WhatsApp bot for development, you need to expose your local server to the internet using **ngrok**.

In a new terminal:

```bash
ngrok http 5000
```

Ngrok will give you a public HTTPS forwarding URL.

Go to:

```
Twilio Console > Messaging > Try it out > Twilio Sandbox for WhatsApp
```

In the **"WHEN A MESSAGE COMES IN"** field, paste your ngrok URL and add `/webhook`:

```
https://your-ngrok-url.ngrok-free.app/webhook
```

Save the configuration. You can now send messages to your Twilio number on WhatsApp to interact with the bot.


