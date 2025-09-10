import re

# Keywords
SCAM_KEYWORDS = {
    "congratulations", "winner", "won", "prize", "claim", "lottery", "gift card",
    "urgent", "verify your account", "account compromised", "security alert",
    "limited time", "offer expires", "click here", "login now", "update your details",
    "earn money", "from home", "investment", "sharan", "guaranteed return", "free gift"
}

# --- NEW: Safe Keywords for quick checks ---
SAFE_KEYWORDS = {
    "hi", "hello", "okay", "ok", "thanks", "thank you", "good morning",
    "good night", "how are you", "what's up", "brb", "lol", "see you",
    "bye", "welcome", "vanakkam", "nptel"
}

# Domains
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".info", ".club", ".live", ".loan", ".buzz", ".vip", 
    ".stream", ".gdn", ".mom", ".lol", ".work"
}

def check_for_scam_keywords(message: str) -> (bool, str | None):
    """Checks if any predefined scam keywords are in the message."""
    message_lower = message.lower()
    for keyword in SCAM_KEYWORDS:
        if keyword in message_lower:
            return True, keyword  
    return False, None

# --- NEW: Function to check for safe keywords in short messages ---
def check_for_safe_keywords(message: str) -> bool:
    """
    Checks if a short message (<= 4 words) contains a predefined safe keyword.
    This helps to quickly approve common greetings and simple phrases.
    """
    message_lower = message.lower().strip()
    if len(message_lower.split()) <= 4:
        for keyword in SAFE_KEYWORDS:
            if keyword in message_lower:
                return True
    return False

def check_for_suspicious_urls(message: str) -> (bool, str | None):
    """Finds all URLs in a message and checks them against the suspicious TLD list."""
    urls = re.findall(r'https?://[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*', message, re.IGNORECASE)
    
    if not urls:
        return False, None

    for url in urls:
        #url check
        for tld in SUSPICIOUS_TLDS:
            if url.lower().endswith(tld) or tld + '/' in url.lower():
                return True, url 
    
    return False, None