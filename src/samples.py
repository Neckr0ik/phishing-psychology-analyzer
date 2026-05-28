"""
Sample texts for demo runs. Spanning the full risk spectrum from benign to critical.
"""

SAMPLES = {
    "Critical: Spear Phishing (CEO Fraud)": (
        "Hi, this is the CEO. I'm in a meeting and absolutely cannot talk right now. "
        "I need you to process an urgent wire transfer immediately — this is time-sensitive "
        "and I need it done within the hour. This is strictly confidential, do not discuss "
        "with anyone in the office. Failure to comply will have serious consequences for "
        "your position. You were specially selected to handle this. Respond immediately."
    ),
    "Critical: Account Threat Email": (
        "URGENT SECURITY ALERT: Your account has been compromised. Our security team detected "
        "unauthorized access from an unknown device. You must verify your identity IMMEDIATELY "
        "or your account will be permanently suspended within 24 hours and legal action may be "
        "initiated. This is your last chance. Click here to verify: http://secure-verify.example "
        "Failure to act will result in account termination and potential criminal investigation."
    ),
    "High: Prize Scam": (
        "Congratulations! You have been exclusively selected as our winner! You have won a "
        "$1,000 gift card. Thousands of people entered but YOU were specially chosen. "
        "This is a limited time offer that expires in 2 hours. Claim your free prize now "
        "before it is given to someone else. Act now — this offer cannot be extended."
    ),
    "High: Tech Support Scam": (
        "CRITICAL WARNING: Our system detected a virus on your device. As the official "
        "Microsoft security team, we are alerting you that your computer has been "
        "compromised and your data is at risk. You must call our tech support immediately "
        "to avoid permanent damage. Do not restart your computer. This is urgent."
    ),
    "Medium: Marketing Email": (
        "Don't miss out! Our annual sale ends Sunday. Join thousands of happy customers "
        "who have already upgraded. As a valued member, you have exclusive early access. "
        "Limited quantities available — shop now before items sell out. "
        "This special offer is for selected customers only."
    ),
    "Medium: Subscription Renewal": (
        "Your subscription expires soon. Renew today to keep your account active and "
        "avoid losing your saved data. As a loyal customer, we are offering you a "
        "discounted renewal rate available only today. Thousands of users have already "
        "renewed. Your information is on file — click to confirm."
    ),
    "Low: Legitimate Bank Notification": (
        "Your monthly account statement is now available. To view your statement, please "
        "log in to your account at our official website using your usual credentials. "
        "If you have any questions about your account, please contact customer service "
        "using the number on the back of your card. Thank you for banking with us."
    ),
    "Low: HR Newsletter": (
        "Hello team, this month's employee newsletter is ready. We are sharing updates "
        "on the company wellness program, upcoming team-building events, and Q3 results. "
        "Please read through and feel free to share feedback with HR at your convenience. "
        "We hope everyone has a great week."
    ),
}
