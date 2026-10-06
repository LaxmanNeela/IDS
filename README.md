# NIDS — Network Intrusion Detection & Threat Mitigation System

## Overview

NIDS is a Python-based Network Intrusion Detection and Threat Mitigation System developed as a practical cybersecurity and machine-learning project.

The project captures network traffic, extracts relevant information, uses a trained machine-learning model to identify suspicious activity, and provides a web interface for monitoring security events.

## Key Features

- Network traffic monitoring using Python and Scapy
- Flow-based packet/network analysis
- Machine-learning-based intrusion detection
- Flask-based web application
- PostgreSQL database integration
- REST API support
- Security event logging
- Threat mitigation workflow
- Web interface for monitoring detected activity

## Technologies Used

- **Python**
- **Flask**
- **Scapy**
- **PostgreSQL**
- **Pandas**
- **NumPy**
- **Scikit-learn**
- **Joblib**
- **HTML / CSS / JavaScript**
- **Git / GitHub**

## Project Structure

```text
NIDS/
├── app/
│   ├── homepage.py
│   └── templates/
│       ├── index.html
│       └── login.html
│
├── model/
│   ├── encoders.pkl
│   ├── feature_means.pkl
│   ├── ids_multi_model.pkl
│   ├── scaler.pkl
│   └── target_encoder.pkl
│
├── scripts/
│   ├── mitigator.py
│   ├── sniffer.py
│   ├── sniffer_flow.py
│   └── train_model.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

## Main Components

### 1. Network Sniffer

The project uses Scapy-based Python scripts to capture and process network traffic.

`sniffer_flow.py` is the flow-based sniffer used for the project's live network monitoring workflow.

### 2. Machine Learning Detection

A trained machine-learning model is used to classify network activity and identify potentially malicious traffic.

The model-related files are stored in the `model/` directory.

### 3. Web Application

The Flask application provides the web interface used to display and work with the detection system.

The main application entry point included in this repository is:

```text
app/homepage.py
```

### 4. Database

PostgreSQL is used to store and manage relevant NIDS/security logs.

### 5. Threat Mitigation

The mitigation component contains the Python logic used as part of the automated threat-response workflow.

## My Contribution

I worked on the Python implementation, network traffic processing, Flask web application, machine-learning integration, PostgreSQL database integration, and debugging of the NIDS workflow.

## How It Works

```text
Network Traffic
       ↓
Traffic Capture
       ↓
Flow / Feature Processing
       ↓
Machine Learning Model
       ↓
Normal / Suspicious Classification
       ↓
Logging & Monitoring
       ↓
Threat Mitigation
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/LaxmanNeela/IDS.git
cd IDS
```

### 2. Create and activate a virtual environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file for database/application configuration.

**Do not commit `.env` to GitHub.**

## Running the Project

Run the Flask application using the project's configured Python entry point.

The exact command may depend on the local configuration of the project.

## Current Status

This is a practical project that is actively being developed and improved. Some components may require additional configuration depending on the operating system, Python environment, network interface, and PostgreSQL setup.

## Important Notes

- Do not commit passwords, API keys, database credentials, tokens, or other secrets.
- The `.env` file is intentionally excluded from this repository.
- The Python virtual environment is intentionally excluded; dependencies are listed in `requirements.txt`.
- The training dataset is not included in the repository.

## Author

**Laxman Neela**

GitHub: [LaxmanNeela](https://github.com/LaxmanNeela)
