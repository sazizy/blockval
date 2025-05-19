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

## 🚀 Getting Started

# 1. Clone the repository
git clone https://github.com/sazizy/blockval.git
cd blockval

# 2. Install dependencies (manual)
pip install -r requirements.txt

# 3. Run master node
python app.py --port 5000 --address http://192.168.x.x:5000 --master 

# 4. Run validator/uploader node
python app.py --port 5001 --address http://192.168.x.x:5000
