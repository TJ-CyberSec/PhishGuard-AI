"""
app.py - Flask Web Application

This web server:
1. Serves the HTML interface
2. Receives form submissions
3. Calls analyzer.py to check emails
4. Stores results in database
5. Returns results to user
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import os
from dotenv import load_dotenv
from analyzer import analyze_email

# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_analyzer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["20 per minute"]
)

# Database Model
class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20))
    red_flags_count = db.Column(db.Integer)
    urls_found = db.Column(db.Integer)

# Routes
@app.route('/')
def home():
    recent_analyses = Analysis.query.order_by(Analysis.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', recent_analyses=recent_analyses)

@app.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    email_text = request.form.get('email_text', '').strip()
    
    if not email_text:
        flash('Please enter email content to analyze', 'error')
        return redirect(url_for('home'))
    
    if len(email_text) > 10000:
        flash('Email content too large (max 10,000 characters)', 'error')
        return redirect(url_for('home'))
    
    try:
        results = analyze_email(email_text)
        
        new_analysis = Analysis(
            risk_score=results['risk_score'],
            risk_level=results['risk_level'],
            red_flags_count=len(results['red_flags']),
            urls_found=len(results['urls_found'])
        )
        db.session.add(new_analysis)
        db.session.commit()
        
        recent_analyses = Analysis.query.order_by(Analysis.timestamp.desc()).limit(10).all()
        
        return render_template('dashboard.html', results=results, recent_analyses=recent_analyses, analyzed_text=email_text[:500])
        
    except Exception as e:
        flash(f'Analysis failed: {str(e)}', 'error')
        return redirect(url_for('home'))

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        print("✅ Database initialized!")

# Run app
if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("🚀 PhishGuard AI - Starting Web Server")
    print("="*60)
    print("🌐 Open your browser to: http://localhost:5000")
    print("⌨️  Press CTRL+C to stop the server")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)