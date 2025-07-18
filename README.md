# Phishing Website Detection Tool

A Python-based tool that detects phishing websites using both rule-based logic and machine learning techniques.

## Features

- **Rule-based detection**: Checks for suspicious patterns in URLs
- **Machine learning**: Uses Random Forest classifier for prediction
- **GUI Interface**: User-friendly graphical interface
- **Visual Analysis**: Shows key URL features in a bar chart
- **Multiple Detection Methods**: Choose between rule-based, ML, or both

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/phishing-website-detector.git
   cd phishing-website-detector
   ```
2.**Create and activate virtual environment**:

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3.**Install dependencies**:

```bash
pip install -r requirements.txt
```
4.**Make it executable**:
```bash
chmod +x phishing_detector.py
```
5.**Run the application**:

```bash
python phishing_detector.py
