# Sentinel-TIP // ML-Driven Cyber Threat Intelligence Platform

> An enterprise-grade, full-stack Threat Intelligence Platform featuring automated OSINT ingestion, XGBoost binary classification, Isolation Forest anomaly detection, and NLP MITRE ATT&CK extraction.

---

## 🚀 Architecture & Core Features

1. **Automated OSINT Ingestion & Normalization**: Pulls live feeds from **Abuse.ch URLHaus**, **Feodo Tracker**, and **AlienVault OTX**, normalizing disparate formats into a unified **STIX 2.1** schema with deduplication and confidence scoring.
2. **Security Feature Engineering**: Converts raw indicators into 14 numerical features spanning **Shannon Entropy** (DGA detection), lexical ratios, syntax profiling, and threat heuristic flags.
3. **Dual Machine Learning Engine**:
   - **XGBoost Classifier**: Scores malicious probability ($0.0 \text{ to } 1.0$) and generates explainable AI (XAI) risk drivers.
   - **Isolation Forest**: Unsupervised anomaly detector flagging novel indicator outliers.
4. **NLP Threat Advisory Parser**: Refangs defanged indicators (`hxxp://`, `[.]`) from raw incident reports and automatically maps text to **MITRE ATT&CK** techniques (`T1566`, `T1059`, `T1071`, `T1105`, `T1190`).
5. **Cyberpunk Glassmorphism Dashboard**: Modern React + Vite frontend featuring live telemetry, interactive on-demand ML scanning, and dark-mode glass styling.

---

## 🛠️ Tech Stack

- **Backend**: FastAPI, SQLAlchemy, Pydantic, Scikit-Learn, XGBoost, Pandas, Requests
- **Frontend**: React, Vite, Lucide Icons, Custom CSS Glassmorphism
- **Storage**: SQLite / PostgreSQL
- **Deployment**: Docker & Docker Compose

---

## 📦 Quick Start with Docker

Ensure you have [Docker](https://www.docker.com/) installed, then run the entire stack with a single command from the project root:

```bash
docker-compose up --build -d