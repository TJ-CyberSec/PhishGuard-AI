"""
analyzer.py - Core Phishing Detection Logic

Using a multi-layer approach to determines if an email is phishing.

1. URL Analysis - Check links against threat databases
2. Content Analysis - Use AI to detect social engineering
3. Risk Scoring - Combine all signals into a final score
"""

import re           #pattern matching in text
import requests     
import validators   #checks if urls are valid
import tldextract   #extracts domain info from urls
from typing import Dict, List, Tuple
import os
from dotenv import load_dotenv
load_dotenv()
from openai import OpenAI   #imports OpenAI class from openai library

client = OpenAI(api_key = os.getenv('OPENAI_API_KEY'))     #client object stores api key

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"        #endpoint
PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"

URGENCY_KEYWORDS = {
    'urgent', 'immediate', 'action required', 'verify now', 'suspended',      
    'expires', 'click here', 'confirm', 'update', 'security alert',
    'unusual activity', 'verify your account', 'locked', 'expire',
    'limited time', 'act now'
}

def extract_urls(email_text: str) -> List[str]:
    """
    Extract all URLs from email text.
    Uses regex to find patterns that look like URLs.
    Returns list of unique URLs found.
    """
    # Regex pattern matches URLs starting with http:// or https://
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, email_text)
    
    # Remove duplicates by converting to set, then back to list
    return list(set(urls))

def check_url_reputation(url: str) -> Dict:
    """
    Check if URL is known malicious using URLhaus database.
    URLhaus is free, no API key needed.
    """
    result = {
        'url': url,
        'is_malicious': False,
        'threat_type': 'unknown',
        'confidence': 'low',
        'source': 'URLhaus'
    }
    
    try:
        # Send POST request to URLhaus API
        response = requests.post(
            URLHAUS_API,
            data={'url': url},
            timeout=5  # Don't wait forever
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # If URLhaus knows this URL, it's malicious
            if data.get('query_status') == 'ok':
                result['is_malicious'] = True
                result['threat_type'] = data.get('threat', 'malware')
                result['confidence'] = 'high'
                
    except Exception as e:         #catching any errors
        print(f"Error checking URL reputation: {e}")
        result['confidence'] = 'unknown'
    
    return result

def analyze_url_safety(url: str) -> Dict:
    """
    Analyze URL for suspicious characteristics.
    Checks for red flags even if not in threat databases.
    """
    result = {
        'url': url,
        'suspicious_factors': [],
        'risk_points': 0
    }
    
    # Extract domain information
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    # RED FLAG 1: Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    if any(url.endswith(tld) for tld in suspicious_tlds):
        result['suspicious_factors'].append('Suspicious TLD commonly used in phishing')
        result['risk_points'] += 25
    
    # RED FLAG 2: IP address instead of domain name
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', extracted.domain):
        result['suspicious_factors'].append('Uses IP address instead of domain name')
        result['risk_points'] += 30
    
    # RED FLAG 3: Very long URL
    if len(url) > 75:
        result['suspicious_factors'].append('Unusually long URL (may hide destination)')
        result['risk_points'] += 15
    
    # RED FLAG 4: Contains @ symbol
    if '@' in url:
        result['suspicious_factors'].append('Contains @ symbol (authentication bypass attempt)')
        result['risk_points'] += 40
    
    return result

#PART 2: EMAIL CONTENT ANALYSIS

def detect_urgency_language(email_text: str) -> Dict:
    """
    Detect urgency and pressure tactics (classic phishing technique).
    Phishing emails create false urgency to make you act without thinking.
    """
    result = {
        'urgency_detected': False,
        'urgency_phrases': [],
        'risk_points': 0
    }
    
    email_lower = email_text.lower()
    
    # Check for each urgency keyword
    for keyword in URGENCY_KEYWORDS:
        if keyword in email_lower:
            result['urgency_phrases'].append(keyword)
    
    # Calculate risk based on how many urgency phrases found
    count = len(result['urgency_phrases'])
    if count > 0:
        result['urgency_detected'] = True
        result['risk_points'] = min(count * 10, 40)  # Max 40 points
    
    return result


def analyze_with_ai(email_text: str) -> Dict:
    """
    Use OpenAI GPT to analyze email for social engineering tactics.
    AI can detect impersonation, emotional manipulation, and authority abuse.
    """
    result = {
        'ai_analysis': '',
        'social_engineering_detected': False,
        'tactics_used': [],
        'risk_points': 0,
        'explanation': ''
    }
    
    try:
        # Create specialized prompt for phishing detection
        prompt = f"""You are a cybersecurity expert analyzing an email for phishing indicators.

Analyze this email and identify:
1. Social engineering tactics (authority, urgency, fear, greed)
2. Impersonation attempts
3. Suspicious requests (credentials, money, clicking links)
4. Red flags in tone or content

Email to analyze:
---
{email_text[:1000]}
---

Provide your analysis in this format:
RISK_LEVEL: [LOW/MEDIUM/HIGH]
TACTICS: [List any social engineering tactics detected]
EXPLANATION: [Brief explanation of why this is/isn't phishing]
"""
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in phishing detection."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=300
        )
        
        # Parse AI response
        ai_response = response.choices[0].message.content
        result['ai_analysis'] = ai_response
        
        # Extract risk level
        if 'HIGH' in ai_response:
            result['risk_points'] = 40
            result['social_engineering_detected'] = True
        elif 'MEDIUM' in ai_response:
            result['risk_points'] = 25
            result['social_engineering_detected'] = True
        else:
            result['risk_points'] = 5
        
        # Extract tactics
        if 'TACTICS:' in ai_response:
            tactics_section = ai_response.split('TACTICS:')[1].split('EXPLANATION:')[0]
            result['tactics_used'] = [t.strip() for t in tactics_section.split(',') if t.strip()]
        
        # Extract explanation
        if 'EXPLANATION:' in ai_response:
            result['explanation'] = ai_response.split('EXPLANATION:')[1].strip()
        
    except Exception as e:
        print(f"AI analysis failed: {e}")
        result['explanation'] = "AI analysis unavailable - using heuristic detection only"
    
    return result

 #PART 3: MASTER ANALYSIS FUNCTION

def analyze_email(email_text: str) -> Dict:
    """
    Master function that orchestrates all detection methods.
    This is what gets called from app.py!
    
    Process:
    1. Extract and check all URLs
    2. Analyze email content for urgency
    3. Get AI analysis
    4. Combine all signals into final risk score
    5. Return comprehensive results
    """
    
    # Initialize results dictionary
    analysis = {
        'risk_score': 0,
        'risk_level': 'SAFE',
        'red_flags': [],
        'urls_found': [],
        'urgency_analysis': {},
        'ai_analysis': {},
        'recommendation': ''
    }
    
    # STEP 1: URL Analysis
    urls = extract_urls(email_text)
    analysis['urls_found'] = urls
    
    for url in urls:
        # Check against threat databases
        reputation = check_url_reputation(url)
        if reputation['is_malicious']:
            analysis['red_flags'].append(
                f"🚨 Malicious URL detected: {url} ({reputation['threat_type']})"
            )
            analysis['risk_score'] += 50
        
        # Check for suspicious characteristics
        safety = analyze_url_safety(url)
        if safety['risk_points'] > 0:
            analysis['risk_score'] += safety['risk_points']
            for factor in safety['suspicious_factors']:
                analysis['red_flags'].append(f"⚠️ {factor}: {url}")
    
    # STEP 2: Urgency Detection
    urgency = detect_urgency_language(email_text)
    analysis['urgency_analysis'] = urgency
    
    if urgency['urgency_detected']:
        analysis['risk_score'] += urgency['risk_points']
        phrases = ', '.join(urgency['urgency_phrases'][:3])
        analysis['red_flags'].append(
            f"⚠️ Urgency language detected: {phrases}"
        )
    
    # STEP 3: AI Analysis
    ai_result = analyze_with_ai(email_text)
    analysis['ai_analysis'] = ai_result
    
    if ai_result['social_engineering_detected']:
        analysis['risk_score'] += ai_result['risk_points']
        if ai_result['tactics_used']:
            tactics = ', '.join(ai_result['tactics_used'])
            analysis['red_flags'].append(
                f"🧠 AI detected social engineering: {tactics}"
            )
    
    # STEP 4: Calculate Final Risk Level
    score = analysis['risk_score']
    
    if score >= 70:
        analysis['risk_level'] = 'MALICIOUS'
        analysis['recommendation'] = '🚨 DO NOT INTERACT - Delete immediately and report to IT'
    elif score >= 40:
        analysis['risk_level'] = 'SUSPICIOUS'
        analysis['recommendation'] = '⚠️ CAUTION - Verify sender through alternate channel before acting'
    else:
        analysis['risk_level'] = 'SAFE'
        analysis['recommendation'] = '✅ No major threats detected, but always verify unexpected requests'
    
    # STEP 5: Add AI explanation to results
    if ai_result['explanation']:
        analysis['ai_explanation'] = ai_result['explanation']
    
    # Cap risk score at 100
    analysis['risk_score'] = min(analysis['risk_score'], 100)
    
    return analysis

