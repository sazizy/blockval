# BLOCKVAL

**BLOCKVAL** (Blockchain Validator) is a private blockchain-based document validation system that integrates **Proof of Authority (PoA)** and **Proof of Work (PoW)** in a hybrid consensus model. The system is designed to improve **accuracy**, **security**, and **efficiency** in validating digital documents within a trusted network, especially in institutional or governmental settings.

---

## 🔧 Features

- Hybrid consensus combining PoA and PoW
- Distributed PoA/PoW ledger for validation and verification
- Digital token issuance and block stamping
- Node roles: uploader, validator, miner, master
- Tamper detection and recovery

---

## 📁 Project Structure
app.py                   # Main Flask application
app-test.py              # Flask application - Hybrid Model for Testing Environment
app-test-poa-only.py     # Flask application - PoA-Only Model for Testing Environment
sqlite_helpers.py        # Local ledger database (SQLite)
mongodb_helpers.py       # MongoDB Atlas helpers for Document and User Database
templates/               # HTML interface (DApps)
static/                  # CSS/images
*.db                     # Local ledger and node registry
evaluation/              # Evaluation results

### Tips:
1. Insert and Change your master node IP Address in app.py or app-test.py or app-test-poa-only.py before run the apps
2. if you run the testing environtment, insert the node slave IP Address to the script

## 🚀 Getting Started

### 1. Clone the repository
git clone https://github.com/sazizy/blockval.git
cd blockval

### 2. Install dependencies (manual)
pip install -r requirements.txt

### 3. Run master node
python app.py --port 5000 --address http://IP_Node_Master:5000 --master 

### 4. Run validator/uploader node
python app.py --port 5000 --address http://IP_Node_Sleve:5000

## ⚠️ Disclaimer
This system is developed strictly for academic and research purposes.
Not intended for production or commercial deployment.

## 👤 Author
Shibron Arby Azizy
📧 shibronazizy@gmail.com
📍 Indonesia
