#!/usr/bin/env python3

import re
import pandas as pd
import numpy as np
import urllib.parse
from urllib.parse import urlparse
import requests
import whois
from datetime import datetime
import socket
import tkinter as tk
from tkinter import ttk, messagebox
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PhishingDetector:
    def __init__(self):
        # Rule-based features
        self.suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'banking', 
                                   'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'chase', 'wells', 'fargo']
        self.legit_tlds = ['.com', '.org', '.net', '.edu', '.gov']
        
        # ML model path
        self.model_path = 'phishing_model.pkl'
        self.model = None
        self.features = None
        
        # Load or train model
        self.load_or_train_model()
    
    def load_or_train_model(self):
        if os.path.exists(self.model_path):
            try:
                model_data = joblib.load(self.model_path)
                self.model = model_data['model']
                self.features = model_data['features']
                print("Model loaded successfully")
            except:
                print("Model file corrupted, retraining...")
                self.train_ml_model()
        else:
            self.train_ml_model()
    
    def train_ml_model(self):
        # Create a more comprehensive dummy dataset
        data = pd.DataFrame({
            'url': [
                'https://www.google.com/search?q=hello',
                'http://phishingsite.com/login.php?user=admin',
                'https://www.amazon.com/gp/buy.html',
                'http://192.168.1.1@evil.com/fake-login',
                'https://captcha-connect.pages.dev/?iduser=TkRnMU1BPT0=&Ri=WF6vK',
                'https://www.paypal.com/account',
                'http://secure-bank-update.com/login',
                'https://www.irs.gov/tax-info',
                'http://facebook.fake.login.page.com',
                'https://www.microsoft.com/en-us/'
            ],
            'label': [0, 1, 0, 1, 1, 0, 1, 0, 1, 0]  # 0 = legitimate, 1 = phishing
        })
        
        # Extract features
        features = []
        for url in data['url']:
            features.append(self.extract_features(url))
        
        # Ensure we have features
        if not features:
            raise ValueError("Feature extraction failed for all URLs")
        
        self.features = list(features[0].keys())
        X = pd.DataFrame(features, columns=self.features)
        y = data['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model trained with accuracy: {accuracy:.2f}")
        
        # Save model with features
        joblib.dump({'model': self.model, 'features': self.features}, self.model_path)
    
    def extract_features(self, url):
        # Initialize default feature values
        default_features = {
            'url_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscore': 0,
            'num_slash': 0,
            'num_question': 0,
            'num_equal': 0,
            'num_at': 0,
            'num_and': 0,
            'num_exclamation': 0,
            'num_space': 0,
            'num_tilde': 0,
            'num_comma': 0,
            'num_plus': 0,
            'num_asterisk': 0,
            'num_hash': 0,
            'num_dollar': 0,
            'num_percent': 0,
            'has_ip': 0,
            'has_https': 0,
            'domain_length': 0,
            'num_subdomains': 0,
            'tld_in_path': 0,
            'tld_in_subdomain': 0,
            'abnormal_url': 0,
            'redirect': 0,
            'short_url': 0,
            'has_port': 0,
            'foreign_chars': 0
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            features = {
                'url_length': len(url),
                'num_dots': url.count('.'),
                'num_hyphens': url.count('-'),
                'num_underscore': url.count('_'),
                'num_slash': url.count('/'),
                'num_question': url.count('?'),
                'num_equal': url.count('='),
                'num_at': url.count('@'),
                'num_and': url.count('&'),
                'num_exclamation': url.count('!'),
                'num_space': url.count(' '),
                'num_tilde': url.count('~'),
                'num_comma': url.count(','),
                'num_plus': url.count('+'),
                'num_asterisk': url.count('*'),
                'num_hash': url.count('#'),
                'num_dollar': url.count('$'),
                'num_percent': url.count('%'),
                'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
                'has_https': 1 if parsed.scheme == 'https' else 0,
                'domain_length': len(domain),
                'num_subdomains': domain.count('.'),
                'tld_in_path': 1 if any(tld in path for tld in self.legit_tlds) else 0,
                'tld_in_subdomain': 1 if any(tld in domain for tld in self.legit_tlds) else 0,
                'abnormal_url': 1 if domain not in url else 0,
                'redirect': 1 if '//' in url[url.find('://')+3:] else 0,
                'short_url': 1 if len(url) < 30 else 0,
                'has_port': 1 if ':' in domain else 0,
                'foreign_chars': 1 if re.search(r'[^\x00-\x7F]', url) else 0
            }
            
            # Ensure no missing features
            for key in default_features:
                if key not in features:
                    features[key] = default_features[key]
            
            return features
        except:
            return default_features
    
    def rule_based_check(self, url):
        """Rule-based phishing detection"""
        score = 0
        reasons = []
        
        # Check 1: URL length
        if len(url) > 75:
            score += 1
            reasons.append("Long URL (common in phishing)")
        
        # Check 2: Contains IP address
        if re.match(r'\d+\.\d+\.\d+\.\d+', url):
            score += 1
            reasons.append("Contains IP address instead of domain name")
        
        # Check 3: Suspicious keywords
        if any(keyword in url.lower() for keyword in self.suspicious_keywords):
            score += 0.5
            reasons.append("Contains sensitive keywords")
        
        # Check 4: Short URL service
        if any(service in url for service in ['bit.ly', 'goo.gl', 'tinyurl']):
            score += 1
            reasons.append("Uses URL shortening service")
        
        # Check 5: @ symbol in URL
        if '@' in url:
            score += 1
            reasons.append("Contains '@' symbol (tricks users)")
        
        # Check 6: Multiple subdomains
        if url.count('.') > 3:
            score += 1
            reasons.append("Multiple subdomains")
        
        # Check 7: HTTPS (lack of)
        if not url.startswith('https://'):
            score += 0.5
            reasons.append("Not using HTTPS")
        
        # Check 8: Domain age
        try:
            domain = urlparse(url).netloc
            if domain:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    
                    age = (datetime.now() - creation_date).days
                    if age < 180:
                        score += 1
                        reasons.append("New domain (often used in phishing)")
        except:
            pass
        
        # Determine result
        if score >= 3:
            return True, reasons
        elif score >= 1.5:
            return True, reasons
        else:
            return False, ["URL appears legitimate"]
    
    def ml_based_check(self, url):
        """Machine learning based detection"""
        if not self.model:
            return False, ["ML model not available"]
        
        try:
            features = self.extract_features(url)
            if not features:
                return False, ["Feature extraction failed"]
            
            # Ensure correct feature order
            feature_values = [features.get(col, 0) for col in self.features]
            X = pd.DataFrame([feature_values], columns=self.features)
            
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0][1]
            
            if prediction == 1:
                return True, [f"Phishing detected with {probability:.2%} confidence"]
            else:
                return False, [f"Legitimate with {1-probability:.2%} confidence"]
        except Exception as e:
            return False, [f"ML analysis failed: {str(e)}"]
    
    def check_url(self, url, method='both'):
        """Check URL using specified method"""
        if method == 'rules':
            return self.rule_based_check(url)
        elif method == 'ml':
            return self.ml_based_check(url)
        else:
            rule_result, rule_reasons = self.rule_based_check(url)
            ml_result, ml_reasons = self.ml_based_check(url)
            
            combined_result = rule_result or ml_result
            combined_reasons = rule_reasons + ml_reasons
            
            return combined_result, combined_reasons

class PhishingDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Website Detector")
        self.root.geometry("800x600")
        self.detector = PhishingDetector()
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('TEntry', font=('Arial', 10))
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        
        self.create_widgets()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Phishing Website Detection Tool", style='Title.TLabel')
        title_label.pack(pady=10)
        
        # URL input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(input_frame, text="Enter URL to analyze:").pack(side=tk.LEFT)
        
        self.url_entry = ttk.Entry(input_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Method selection
        method_frame = ttk.Frame(main_frame)
        method_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(method_frame, text="Detection Method:").pack(side=tk.LEFT)
        
        self.method_var = tk.StringVar(value='both')
        ttk.Radiobutton(method_frame, text="Both", variable=self.method_var, value='both').pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(method_frame, text="Rule-based", variable=self.method_var, value='rules').pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(method_frame, text="Machine Learning", variable=self.method_var, value='ml').pack(side=tk.LEFT, padx=5)
        
        # Analyze button
        analyze_button = ttk.Button(main_frame, text="Analyze URL", command=self.analyze_url)
        analyze_button.pack(pady=10)
        
        # Results frame
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Result display
        self.result_text = tk.Text(results_frame, wrap=tk.WORD, height=10, font=('Arial', 10))
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Visualization frame
        self.viz_frame = ttk.Frame(results_frame)
        self.viz_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X)
    
    def analyze_url(self):
        url = self.url_entry.get().strip()
        method = self.method_var.get()
        
        if not url:
            messagebox.showerror("Error", "Please enter a URL to analyze")
            return
        
        # Add http:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        self.status_var.set("Analyzing URL...")
        self.root.update()
        
        try:
            # Check URL
            is_phishing, reasons = self.detector.check_url(url, method)
            
            # Display results
            self.result_text.delete(1.0, tk.END)
            
            if is_phishing:
                self.result_text.insert(tk.END, "WARNING: This URL appears to be a phishing site!\n\n", 'warning')
            else:
                self.result_text.insert(tk.END, "This URL appears to be legitimate.\n\n", 'safe')
            
            self.result_text.insert(tk.END, "Analysis Results:\n")
            for reason in reasons:
                self.result_text.insert(tk.END, f"- {reason}\n")
            
            # Add URL details
            parsed = urlparse(url)
            self.result_text.insert(tk.END, "\nURL Details:\n")
            self.result_text.insert(tk.END, f"Scheme: {parsed.scheme}\n")
            self.result_text.insert(tk.END, f"Domain: {parsed.netloc}\n")
            self.result_text.insert(tk.END, f"Path: {parsed.path}\n")
            
            # Configure tags for colored text
            self.result_text.tag_config('warning', foreground='red')
            self.result_text.tag_config('safe', foreground='green')
            
            # Create visualization
            self.create_visualization(url)
            
            self.status_var.set("Analysis complete")
        except Exception as e:
            self.status_var.set("Error occurred")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def create_visualization(self, url):
        # Clear previous visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        # Extract features for visualization
        features = self.detector.extract_features(url)
        
        # Select key features to display
        key_features = {
            'URL Length': features['url_length'],
            'Has IP': features['has_ip'],
            'Uses HTTPS': features['has_https'],
            'Subdomains': features['num_subdomains'],
            '@ Symbols': features['num_at'],
            'Suspicious Chars': features['foreign_chars']
        }
        
        # Create figure
        fig, ax = plt.subplots(figsize=(6, 4))
        y_pos = np.arange(len(key_features))
        
        ax.barh(y_pos, list(key_features.values()), align='center')
        ax.set_yticks(y_pos)
        ax.set_yticklabels(list(key_features.keys()))
        ax.set_xlabel('Value')
        ax.set_title('URL Feature Analysis')
        
        # Embed in Tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.viz_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def main():
    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()