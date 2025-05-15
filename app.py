from doctest import master
from flask import Flask, flash, json, jsonify, redirect, render_template, request, send_file, session, url_for
from datetime import datetime, timezone
from functools import wraps
from hashlib import sha256
from uuid import uuid4
from bson import ObjectId
from gridfs import GridFS
from argparse import ArgumentParser
import gridfs
from passlib.hash import sha256_crypt
from io import BytesIO
import io, sys, logging, os, socket, base64, zlib, psutil, requests, time, threading, hashlib, qrcode
import atexit
import fitz

from mongodb_helpers import *
from sqlite_helpers import *
from forms import *


app = Flask(__name__)

# MongoDB helper instance
mongodb_name = 'db_blockval0_2'
mongo_server = 'mongodb+srv://ShibronAzizy:shibronazizy@cluster0.nfgfk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
blockval_mongodb = MongoDBHelper(mongo_server, mongodb_name)

# Sqlite helper instance
# Inisialisasi active_nodes.db
active_nodes = SQLiteHelper('active_nodes.db', 'active_nodes', [
    'node_address'
])

# # Inisialisasi database

# Variabel global untuk menyimpan alamat node master
# NODE_MASTER = "http://192.168.230.138:5000"
# NODE_MASTER = "http://192.168.119.138:5000"
NODE_MASTER = "http://192.168.0.176:5000"
node_identifier = str(uuid4()).replace('-', '')
mining_in_progress = False
# Buffer untuk menampung hasil mining sementar
pending_pow_blocks = []
pow_selection_timer = None
last_finalized_time = 0
last_finalized_block_number = None


# ledger pow
ledger_pow = SQLiteHelper('ledger.db', 'ledger_pow', [
    'number', 'hash', 'previous_hash', 'poa_hash', 'nonce',
    'project_name', 'document_name', 'document_id', 'document_hash',
    'balai_validator_name', 'balai_mac_address', 'balai_location', 'balai_timestamp', 'balai_token',
    'kompetensi_validator_name', 'kompetensi_mac_address', 'kompetensi_location', 'kompetensi_timestamp', 'kompetensi_token',
    'ki_validator_name', 'ki_mac_address', 'ki_location', 'ki_timestamp', 'ki_token',
    'data_miner', 'timestamp_miner'
])

# ledger poa
ledger_poa = SQLiteHelper('ledger.db', 'ledger_poa', [
    'number', 'hash', 'previous_hash',
    'project_name', 'document_name', 'document_id', 'document_hash',
    'balai_validator_name', 'balai_mac_address', 'balai_location', 'balai_timestamp', 'balai_token',
    'kompetensi_validator_name', 'kompetensi_mac_address', 'kompetensi_location', 'kompetensi_timestamp', 'kompetensi_token',
    'ki_validator_name', 'ki_mac_address', 'ki_location', 'ki_timestamp', 'ki_token'
])

def initialize_ledger():
    # Cek apakah ledger_poa kosong, jika ya, tambahkan Genesis Block
    poa_block_genesis_hash = sha256("GENESIS_BLOCK_POA".encode()).hexdigest()
    if len(ledger_poa.fetch_all('ledger_poa')) == 0:
        print("📌 Menambahkan Genesis Block ke ledger_poa...")
        ledger_poa.insert_record('ledger_poa', [
            "1",  # Block Number
            poa_block_genesis_hash,  # Hash Block
            "0" * 64,  # Previous Hash (Default untuk Genesis Block)
            "GENESIS", # Project Name
            "NULL", # Document Name
            "0",  # Document ID (NULL)
            "NULL",  # Document Hash (NULL)
            "NULL",  # Balai Validator
            "NULL",  # Balai MAC
            "NULL",  # Balai Location
            datetime.now(timezone.utc).isoformat(),  # Timestamp Genesis
            "NULL",  # Balai Token
            "NULL",  # Kompetensi Validator
            "NULL",  # Kompetensi MAC
            "NULL",  # Kompetensi Location
            datetime.now(timezone.utc).isoformat(),  # Timestamp Genesis
            "NULL",  # Kompetensi Token
            "NULL",  # KI Validator
            "NULL",  # KI MAC
            "NULL",  # KI Location
            datetime.now(timezone.utc).isoformat(),  # Timestamp Genesis
            "NULL"  # KI Token
        ])

    # Cek apakah ledger_pow kosong, jika ya, tambahkan Genesis Block
    if len(ledger_pow.fetch_all('ledger_pow')) == 0:
        print("📌 Menambahkan Genesis Block ke ledger_pow...")
        ledger_pow.insert_record('ledger_pow', [
            "1",  # Block Number
            sha256("GENESIS_BLOCK_POW".encode()).hexdigest(),  # Hash Block
            "0" * 64,  # Previous Hash (Default untuk Genesis Block)
            poa_block_genesis_hash, #poa hash
            "GENESIS", # Nonce
            "NULL", # Project Name
            "NULL", # Document Name
            "0",  # Document ID (NULL)
            "NULL",  # Document Hash (NULL)
            "NULL",  # Balai Validator
            "NULL",  # Balai MAC
            "NULL",  # Balai Location
            datetime.now(timezone.utc).isoformat(),  # Timestamp Genesis
            "NULL",  # Balai Token
            "NULL",  # Kompetensi Validator
            "NULL",  # Kompetensi MAC
            "NULL",  # Kompetensi Location
            datetime.now(timezone.utc).isoformat(),  # Timestamp Genesis
            "NULL",  # Kompetensi Token
            "NULL",  # KI Validator
            "NULL",  # KI MAC
            "NULL",  # KI Location
            datetime.now(timezone.utc).isoformat(),  # Timestamp Genesis
            "NULL",  # KI Token
            "NULL",  # Data Miner
            datetime.now(timezone.utc).isoformat()  # Timestamp Miner
        ])

initialize_ledger()

def updatehash(*args):
    hashing_text = "".join(map(str, args))
    return sha256(hashing_text.encode('utf-8')).hexdigest()

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'blockval_logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized User, Please Login First.', 'danger')
            return redirect(url_for('login'))
    return wrap

def log_in_user(username):
    user = blockval_mongodb.find_data('users', {'username': username})

    session['blockval_logged_in'] = True
    session['username'] = username
    session['name'] = user.get('full_name')
    session['email'] = user.get('email')
    session['role'] = user.get('jenis_user')

def get_primary_mac_address():
    try:
        # 🔹 Dapatkan alamat IP yang digunakan untuk koneksi internet (bukan localhost)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS sebagai tujuan untuk menentukan IP lokal
        local_ip = s.getsockname()[0]
        s.close()

        print(f"🌐 IP yang digunakan untuk koneksi internet: {local_ip}")

        # 🔹 Ambil daftar semua interface & alamatnya
        net_if_addrs = psutil.net_if_addrs()

        for interface_name, interface_addresses in net_if_addrs.items():
            mac_address = None
            has_ip = False

            for address in interface_addresses:
                if address.family == socket.AF_INET and address.address == local_ip:
                    has_ip = True  # Interface ini adalah yang digunakan untuk internet
                elif address.family == psutil.AF_LINK:  # MAC Address
                    mac_address = address.address.upper()

            # Jika interface memiliki IP yang cocok dengan IP internet, ambil MAC-nya
            if has_ip and mac_address:
                print(f"✅ MAC Address utama ditemukan pada {interface_name}: {mac_address}")
                return mac_address

        print("❌ Tidak ada MAC Address utama yang ditemukan.")
        return None  # Jika tidak ada yang ditemukan

    except Exception as e:
        print(f"⚠️ ERROR: {e}")
        return None

def get_location():
    try:
        response = requests.get("https://ipinfo.io/", timeout=5)
        data = response.json()
        city = data.get('city', 'Unknown')
        region = data.get('region', 'Unknown')
        country = data.get('country', 'Unknown')
        return f"{city}, {region}, {country}"
    
    except Exception as e:
        print(f"🌐 ERROR get_location(): {e}")
        return "Unknown"

def encode_token(data):
    # Ubah data menjadi string JSON
    token_string = json.dumps(data)
    # Kompres data menggunakan zlib
    compressed_data = zlib.compress(token_string.encode())
    # Encode kompresi menjadi Base64
    token_encoded = base64.b64encode(compressed_data).decode()
    return token_encoded

def decode_token(token):
    # Decode token dari Base64 ke kompresi
    compressed_data = base64.b64decode(token.encode())
    # Dekompres data
    token_string = zlib.decompress(compressed_data).decode()
    # Ubah string JSON menjadi dictionary
    data = json.loads(token_string)
    return data


def shutdown_handler():
    """
    Handler untuk menghapus node dari database saat program dimatikan.
    """
    print("Shutdown handler dipanggil.")
    
    try:
        # Hapus node dari database lokal
        active_nodes.delete("active_nodes", f"node_address = '{node_address}'")
        print(f"Node {node_address} berhasil dihapus dari database lokal.")
        
        # Jika ini adalah node slave, beri tahu node master untuk menghapus node ini dari daftar aktif
        if not args.master:
            try:
                requests.post(f"{NODE_MASTER}/nodes/remove", json={"node": node_address})
                print(f"Node {node_address} berhasil dihapus dari node master.")
            except requests.exceptions.RequestException as e:
                print(f"Tidak dapat menghapus node dari jaringan: {e}")
    except Exception as e:
        print(f"Gagal menghapus node dari database lokal: {e}")

    active_nodes.clear_table("active_nodes")  # Hapus daftar lama
    print("✅ Semua daftar Node lama di hapus pada database lokal.")
    os._exit(0)

def check_document_status(document_hash):
    """
    Mengembalikan status dokumen:
    - 'valid' jika sudah dinyatakan valid
    - 'invalid' jika sudah dinyatakan tidak valid
    - 'in_progress' jika sedang divalidasi
    - None jika belum pernah diajukan
    """
    doc = blockval_mongodb.find_data('documents', {'document_hash': document_hash})
    if doc:
        status = doc.get('isValid')
        if status == 'true':
            return 'valid'
        elif status == 'false':
            return 'invalid'
        elif status == 'none':
            return 'in_progress'

    valid_doc = blockval_mongodb.find_data('valid_docs', {'new_document_hash': document_hash})
    if valid_doc:
        status = valid_doc.get('isValid')
        if status == 'true':
            return 'valid'
        elif status == 'false':
            return 'invalid'
        elif status == 'none':
            return 'in_progress'

    return None  # belum pernah diajukan


def attach_qrcode_to_pdf(document):
    """
    Mengambil PDF dari GridFS, menempelkan QR Code, dan menyimpannya kembali ke GridFS.
    Hasil PDF disimpan di koleksi 'valid_docs'.
    """
    print(f"🔄 Node {node_address} masuk ke method attach_qrcode_to_pdf.")
    # 🔹 Koneksi ke MongoDB
    client = MongoClient(mongo_server)
    db = client[mongodb_name]
    fs = gridfs.GridFS(db)

    # 🔹 Ambil metadata dokumen dari koleksi 'documents'
    document_id = str(document['document_id'])

    if not document or 'document_hash' not in document:
        return None, "Dokumen tidak ditemukan atau belum divalidasi."

    document_hash = document['document_hash']

    # 🔹 Ambil blok PoA berdasarkan `document_hash`
    poa_block = ledger_poa.fetch_one("ledger_poa", f"document_hash = '{document_hash}'")
    if not poa_block:
        return None, "Blok PoA tidak ditemukan untuk dokumen ini."

    # 🔹 Ambil file PDF dari GridFS
    try:
        original_pdf = fs.get(ObjectId(document_id)).read()
    except gridfs.errors.NoFile:
        return None, "File PDF tidak ditemukan di GridFS."

    # 🔹 Buat data QR Code berisi informasi Blok PoA
    qr_data = {
        "block_number": poa_block[0],
        "poa_hash": poa_block[1],
        "previous_hash": poa_block[2],
        "project_name": poa_block[3],
        "document_name": poa_block[4],
        "document_id": poa_block[5],
        "document_hash": poa_block[6],
        "balai_token": poa_block[11],
        "kompetensi_token": poa_block[16],
        "ki_token": poa_block[21]
    }
    qr_data_json = json.dumps(qr_data, indent=4)

    # 🔹 Generate QR Code
    qr = qrcode.make(qr_data_json)
    qr_io = BytesIO()
    qr.save(qr_io, format="PNG")
    qr_io.seek(0)

    # 🔹 Buka PDF asli dengan PyMuPDF
    try:
        pdf_document = fitz.open("pdf", original_pdf)
        print(f"🔄 Node {node_address} membuka file pdf dokumen {poa_block[4]}.")
    except Exception as e:
        return None, f"Gagal membuka PDF: {str(e)}"
    
    # 🔹 Tempelkan QR Code di halaman pertama
    try:
        page = pdf_document[0]  # Halaman pertama
        page_height = page.rect.height
        qr_size = 80 # Ukuran QR Code kecil (80x80 pt)
        rect = fitz.Rect(30, page_height - qr_size - 30, 30 + qr_size, page_height - 30)
        page.insert_image(rect, stream=qr_io.read(), keep_proportion=True)
        print(f"🔄 Node {node_address} menempelkan qrcode ke pdf dan disimpan ke pdf baru.")
    except Exception as e:
        return None, f"Gagal menempelkan QR Code: {str(e)}"

    # 🔹 Simpan hasil PDF ke dalam memory
    output_pdf = BytesIO()
    try:
        pdf_document.save(output_pdf)
        output_pdf.seek(0)
        print(f"🔄 Node {node_address} menyimpan pdf ke memori.")
    except Exception as e:
        return None, f"Gagal menyimpan PDF: {str(e)}"
    
    # 🔹 Hitung `new_document_hash` setelah QR Code ditempel
    new_document_hash = sha256(output_pdf.getvalue()).hexdigest()

    # 🔹 Simpan hasil PDF ke GridFS dalam koleksi 'valid_docs'
    try:
        new_document_id = fs.put(output_pdf.getvalue(), uploader=document['uploader'], 
                                 project_name=document['project_name'], 
                                 document_name=document['document_name'], 
                                 document_hash=document_hash,
                                 new_document_hash=new_document_hash)
        print(f"🔄 Node {node_address} menyimpan dokumen {poa_block[4]} ke gridfs.")
    except Exception as e:
        return None, f"Gagal menyimpan PDF ke GridFS: {str(e)}"
    
    # 🔹 Simpan metadata ke koleksi valid_docs
    try:
        document['_id'] = ObjectId()  # Gunakan ID baru
        document['document_id'] = new_document_id  # ID baru di GridFS
        document['isValid'] = 'true'
        document['new_document_hash'] = new_document_hash  # Simpan hash baru
        blockval_mongodb.insert_data("valid_docs", document)  # Simpan metadata baru
        print(f"🔄 Node {node_address} menyimpan dokumen {poa_block[4]} ke collection valid_doc dengan hash baru: {new_document_hash}.")
    except Exception as e:
        return None, f"Gagal menyimpan metadata: {str(e)}"
    
    print(f"🔄 Node {node_address} berhasil menyimpan dokumen {poa_block[4]} ke collection valid_doc.")
    return new_document_id, None  # Return ID dokumen baru

# === STATUS VALIDASI DI NODE MASTER ===
validation_in_progress = False
current_validator = None  # nama validator yang sedang memegang validasi

@app.route('/is_validation_in_progress', methods=['GET'])
def is_validation_in_progress():
    return jsonify({"in_progress": validation_in_progress})

@app.route('/set_validation_status', methods=['POST'])
def set_validation_status():
    global validation_in_progress, current_validator
    data = request.get_json()
    status = data.get("in_progress")
    validator = data.get("validator")

    if isinstance(status, bool):
        if status:
            if validation_in_progress:
                print(f"❌ Permintaan validasi dari {validator} ditolak. Sudah ada validasi aktif oleh {current_validator}.")
                return jsonify({"message": f"Validasi sedang berlangsung oleh {current_validator}"}), 409
            validation_in_progress = True
            current_validator = validator
            print(f"✅ Validasi dimulai oleh {validator}")
        else:
            if validator == current_validator:
                validation_in_progress = False
                current_validator = None
                print(f"✅ Validasi selesai oleh {validator}")
            else:
                print(f"❌ {validator} mencoba menghentikan validasi yang bukan miliknya ({current_validator})")
                return jsonify({"message": "Anda bukan pemegang validasi aktif"}), 403
        return jsonify({"message": "Status diperbarui"}), 200

    return jsonify({"message": "Format salah"}), 400

# === FUNGSI DI NODE VALIDATOR ===
def wait_until_master_idle():
    while True:
        try:
            response = requests.get(f"{NODE_MASTER}/is_validation_in_progress")
            if response.status_code == 200:
                data = response.json()
                if not data.get("in_progress", False):
                    break
                print(f"⏳ Menunggu giliran validasi... sedang diproses oleh: {data.get('validator', '-')}")
        except:
            pass
        time.sleep(2)

#=====================================================================================================================================
#============================================   START METHOD BROADCAST   =============================================================
#=====================================================================================================================================
def broadcast_new_poa_block(new_block):
    """
    Mengirim ledger PoA terbaru ke seluruh node dalam jaringan dengan mekanisme retry.
    """
    active_nodes_list = active_nodes.fetch_all("active_nodes")
    nodes = [row[0] for row in active_nodes_list]

    for node in nodes:
        if node == node_address:  # Lewati node sendiri
            continue
        
        try:
            response = requests.post(f"{node}/add_poa_block", json={"block": new_block})
            if response.status_code == 200:
                print(f"✅ Ledger PoA terbaru dikirim ke {node}")
            else:
                print(f"⚠️ {node} menolak hasil mining.")
        except requests.exceptions.RequestException:
            print(f"⚠️ Gagal menghubungi node {node}.")

#=====================================================================================================================================
#============================================   END METHOD BROADCAST   ===============================================================
#=====================================================================================================================================

#=====================================================================================================================================
#============================================   START METHOD LEDGER VALIDATION   =====================================================
#=====================================================================================================================================
def validate_ledger(ledger=None, ledger_type='poa'):
    """
    Memeriksa apakah ledger yang diberikan valid.
    Jika ledger tidak diberikan, akan mengambil ledger lokal dari database.
    ledger_type: 'poa' atau 'pow'
    """
    try:
        if ledger is None:
            ledger = ledger_poa.fetch_all('ledger_poa') if ledger_type == 'poa' else ledger_pow.fetch_all('ledger_pow')

        if len(ledger) <= 1:
            return True  # Ledger hanya berisi Genesis Block, dianggap valid

        for i in range(1, len(ledger)):
            current_block = ledger[i]
            prev_block = ledger[i - 1]

             # 1️⃣ Periksa previous hash
            if current_block[2] != prev_block[1]:  # Periksa previous_hash
                print(f"PADA NODE: {node_address} ❌ ERROR: Ledger {ledger_type.upper()} tidak valid di block {current_block[0]}.")
                return False
            
            if ledger_type == 'poa':
                # 2️⃣ Recalculate hash dari seluruh data blok (tanpa hash)
                recalculated_hash = updatehash(
                    current_block[0],  # number
                    current_block[2],  # previous_hash
                    current_block[3],  # project_name
                    current_block[4],  # document_name
                    current_block[5],  # document_id
                    current_block[6],  # document_hash

                    current_block[7],  # balai_validator_name
                    current_block[8],  # balai_mac_address
                    current_block[9],  # balai_location
                    current_block[10], # balai_timestamp
                    current_block[11], # balai_token

                    current_block[12], # kompetensi_validator_name
                    current_block[13], # kompetensi_mac_address
                    current_block[14], # kompetensi_location
                    current_block[15], # kompetensi_timestamp
                    current_block[16], # kompetensi_token

                    current_block[17], # ki_validator_name
                    current_block[18], # ki_mac_address
                    current_block[19], # ki_location
                    current_block[20], # ki_timestamp
                    current_block[21]  # ki_token
                )

                if recalculated_hash != current_block[1]:
                    print(f"❌ Ledger PoA Invalid: Hash tidak sesuai pada block #{current_block[0]}")
                    return False
                
            elif ledger_type == 'pow':
                # 3️⃣ Validasi seluruh isi blok (selain hash dan nonce)
                nonce = current_block[4]
                block_data = current_block[0:1] + current_block[2:4] + current_block[5:]  # Skip current_block[1] (hash) dan current_block[1] (nonce)

                data_string = "".join(str(item) for item in block_data) + str(nonce)
                recalculated_hash = hashlib.sha256(data_string.encode()).hexdigest()

                if recalculated_hash != current_block[1] or not recalculated_hash.startswith("0000"):
                    print(f"❌ Ledger PoW INVALID: Hash atau nonce tidak valid di block #{current_block[0]}")
                    return False
                
                # **Tambahan validasi ketergantungan ledger PoW dengan ledger PoA**
                corresponding_poa_block = ledger_poa.fetch_one("ledger_poa", f"number = '{current_block[0]}'")
                if corresponding_poa_block:
                    poa_hash = corresponding_poa_block[1]  # Hash dari ledger PoA
                    if current_block[3] != poa_hash:  # Periksa apakah poa_hash di PoW sesuai dengan hash di PoA
                        print(f"❌ Ledger PoW Invalid: PoA Hash tidak sesuai di blok #{current_block[0]}")
                        return False
        
        return True
    except Exception as e:
        print(f"❌ ERROR: Gagal memvalidasi ledger {ledger_type.upper()}: {str(e)}")
        return False

def is_valid_ledger(ledger_type='poa'):
    """
    Memeriksa apakah ledger lokal valid. Jika tidak, mencari ledger valid dari node lain.
    Jika lebih dari 30% blok rusak, mengganti seluruh ledger. Jika kurang dari 30%, hanya memperbaiki blok rusak.
    ledger_type: 'poa' atau 'pow'
    """
    ledger = ledger_poa.fetch_all('ledger_poa') if ledger_type == 'poa' else ledger_pow.fetch_all('ledger_pow')
    
    if validate_ledger(ledger, ledger_type):
        print(f"🔍 Ledger {ledger_type.upper()} valid...")
        return True  # Ledger sudah valid

    print(f"🔍 Ledger {ledger_type.upper()} tidak valid, mengevaluasi tingkat kerusakan...")

    # Hitung jumlah blok yang rusak
    invalid_blocks = []
    for i in range(1, len(ledger)):
        if ledger[i][2] != ledger[i - 1][1]:  # Cek previous_hash
            invalid_blocks.append(ledger[i][0])  # Simpan nomor blok yang rusak

    # Jika lebih dari 30% blok rusak, ganti seluruh ledger
    if len(invalid_blocks) > (0.3 * len(ledger)):
        print(f"⚠️ Banyak blok yang rusak ({len(invalid_blocks)} dari {len(ledger)})! Mengganti seluruh ledger {ledger_type.upper()}...")
        longest_valid_ledger = find_longest_valid_ledger(ledger_type)
        if longest_valid_ledger:
            replace_ledger(longest_valid_ledger, ledger_type)
            print(f"✅ Ledger {ledger_type.upper()} berhasil diganti dengan yang valid.")
            return True
        else:
            print(f"⚠️ Tidak ditemukan ledger {ledger_type.upper()} yang valid di jaringan.")
            return False
    else:
        print(f"⚠️ Hanya {len(invalid_blocks)} blok yang rusak. Mencoba perbaikan selektif...")
        return repair_ledger(ledger, invalid_blocks, ledger_type)  # Memperbaiki blok tertentu saja


def find_longest_valid_ledger(ledger_type='poa'):
    """
    Mengambil ledger terpanjang yang valid dari node lain.
    """

    active_nodes_list = active_nodes.fetch_all("active_nodes")
    nodes = [row[0] for row in active_nodes_list]

    longest_ledger = None
    max_length = 0
    
    chain_endpoint = '/poa_chain' if ledger_type == 'poa' else '/pow_chain'
    for node in nodes:
        if node == node_address:  # Lewati node sendiri
            continue

        try:
            response = requests.get(f"{node}{chain_endpoint}", timeout=10)
            if response.status_code == 200:
                ledger_data = response.json()["chain"]
                length_ledger_data = response.json()["length"]
                
                if length_ledger_data > max_length and validate_ledger(ledger_data, ledger_type):
                    longest_ledger = ledger_data
                    max_length = length_ledger_data
        
        except requests.exceptions.RequestException:
            print(f"⚠️ Tidak dapat menghubungi node {node} untuk mendapatkan ledger {ledger_type.upper()}.")
    
    return longest_ledger

def replace_ledger(new_ledger, ledger_type='poa'):
    """
    Mengganti ledger lokal dengan ledger baru yang valid.
    """
    target_ledger = ledger_poa if ledger_type == 'poa' else ledger_pow
    target_ledger.clear_table(f"ledger_{ledger_type}")
    
    for block in new_ledger:
        target_ledger.insert_record(f"ledger_{ledger_type}", block)

    print(f"✅ Ledger {ledger_type.upper()} telah diperbarui dengan REPLACE.")

def repair_ledger(ledger, invalid_blocks, ledger_type='poa'):
    """
    Memperbaiki hanya blok yang rusak dengan UPDATE tanpa menghapus dan mengurutkan ulang ledger setelah perbaikan.
    """
    longest_valid_ledger = find_longest_valid_ledger(ledger_type)
    print(f"⚠️ Masuk ke method repair_ledger().")

    if not longest_valid_ledger:
        print(f"⚠️ Tidak ditemukan ledger {ledger_type.upper()} yang valid untuk perbaikan selektif.")
        return False

    fixed_blocks = 0
    target_ledger = ledger_poa if ledger_type == 'poa' else ledger_pow

    # **🔹 Ambil daftar kolom dari database untuk memastikan kompatibilitas**
    column_names = target_ledger.get_column_names(f'ledger_{ledger_type}')

    print(f"⚠️ Ledger yang di-repair adalah: ledger_{ledger_type}.")
    print(f"⚠️ Blok-blok yang rusak: {invalid_blocks}.")

    for block_number in invalid_blocks:
        # Ambil blok saat ini dari ledger
        current_block = next((blk for blk in ledger if int(blk[0]) == int(block_number)), None)

        if not current_block:
            continue

        # Cari blok yang sesuai dari ledger valid terpanjang
        valid_block = next((blk for blk in longest_valid_ledger if int(blk[0]) == int(block_number)), None)

        if valid_block and current_block != valid_block:
            print(f"🔄 Memperbarui blok #{block_number} dengan versi yang benar dari ledger terpanjang...")

            # **🔹 Buat dictionary hanya dengan kolom yang tersedia di tabel**
            update_data = {
                column: valid_block[i] for i, column in enumerate(column_names) if i < len(valid_block)
            }

            # **Lakukan UPDATE hanya untuk kolom yang ada di tabel**
            target_ledger.update_record(
                f'ledger_{ledger_type}',
                update_data,
                f"number = {block_number}"  # Hanya update blok tertentu
            )

            fixed_blocks += 1
            print(f"✅ Ledger {ledger_type.upper()} blok #{block_number} telah diperbarui.")

    if fixed_blocks > 0:
        print(f"✅ {fixed_blocks} blok rusak telah diperbaiki dan ledger tetap terurut.")
    else:
        print(f"⚠️ Tidak ada blok yang perlu diperbaiki.")

    return fixed_blocks > 0

#=====================================================================================================================================
#============================================   END METHODS LEDGER VALIDATION   ======================================================
#=====================================================================================================================================

#=====================================================================================================================================
#============================================   POA POW METHOD   =====================================================================
#=====================================================================================================================================
@app.route('/add_poa_block', methods=['POST'])
def add_poa_block():
    """
    Menerima blok PoA baru dan menambahkannya ke ledger jika belum ada.
    """

    data = request.get_json()
    new_block = data.get("block", [])

    if not new_block or len(new_block) < 22:  # Cek struktur blok sesuai ledger poa
        return jsonify({"message": "Blok PoA tidak valid"}), 400

    existing_block = ledger_poa.fetch_one("ledger_poa", f"number = '{new_block[0]}' AND hash = '{new_block[1]}'")
    if existing_block:
        print(f"ℹ️ Blok PoA #{new_block[0]} sudah ada di ledger. Abaikan duplikat.")
        return jsonify({"message": "Blok sudah ada, tidak disimpan ulang."}), 200

    last_block = ledger_poa.fetch_last("ledger_poa")
    if is_valid_ledger('poa'):
        if last_block and int(new_block[0]) > int(last_block[0]):  # Cek apakah blok ini lebih baru
            ledger_poa.insert_record("ledger_poa", new_block)
            # print(f"✅ Blok PoA #{new_block[0]} ditambahkan ke ledger. Memulai mining PoW...")
            print(f"✅ Blok PoA #{new_block[0]} ditambahkan ke ledger dari endpoint /add_poa_block. Memulai mining PoW...")

            if not args.master:
                # 🔄 **Mulai mining PoW setelah blok PoA ditambahkan**
                pow_thread = threading.Thread(target=start_mining_pow)
                pow_thread.daemon = True
                pow_thread.start()

            return jsonify({"message": "Blok PoA ditambahkan"}), 200
        else:
            return jsonify({"message": "Blok PoA bukan blok baru"}), 400
    else:
        return jsonify({"message": "Blok PoA sudah ada atau tidak valid"}), 400

def proof_of_authority(document):
    """
    Menambahkan blok ke ledger POA setelah dokumen divalidasi oleh semua validator.
    """
    try:
        # 🔹 Ambil Previous Block dari ledger_poa
        previous_block = ledger_poa.fetch_last('ledger_poa')
        print(f"🔄 Pada Node {node_address} masuk ke method proof_of_authority.")

        if previous_block:
            previous_hash = previous_block[1]  # Hash dari previous block
            block_number = int(previous_block[0]) + 1  # Nomor block berikutnya
        else:
            previous_hash = "0" * 64  # Genesis Block
            block_number = 1

        # 🔹 Ambil token validator
        balai_token = document.get('balai_token', '')
        kompetensi_token = document.get('kompetensi_token', '')
        ki_token = document.get('ki_token', '')

        # 🔹 Decode token untuk mendapatkan data validator
        balai_data = decode_token(balai_token) if balai_token and balai_token != "invalid" else {}
        kompetensi_data = decode_token(kompetensi_token) if kompetensi_token and kompetensi_token != "invalid" else {}
        ki_data = decode_token(ki_token) if ki_token and ki_token != "invalid" else {}

        # 🔹 Hitung hash blok baru dengan `updatehash()`
        hash_current_block = updatehash(
            block_number,
            previous_hash,
            document['project_name'],
            document['document_name'],
            str(document['document_id']),
            document['document_hash'],
            balai_data.get('validator_name', ''), 
            balai_data.get('mac_address', ''), 
            balai_data.get('location', ''),
            balai_data.get('timestamp', ''), 
            balai_token,
            kompetensi_data.get('validator_name', ''), 
            kompetensi_data.get('mac_address', ''), 
            kompetensi_data.get('location', ''),
            kompetensi_data.get('timestamp', ''), 
            kompetensi_token,
            ki_data.get('validator_name', ''), 
            ki_data.get('mac_address', ''), 
            ki_data.get('location', ''),
            ki_data.get('timestamp', ''), 
            ki_token
        )

        new_block = [
            block_number, hash_current_block, previous_hash,
            document['project_name'], document['document_name'], str(document['document_id']), document['document_hash'],
            balai_data.get('validator_name', ''), balai_data.get('mac_address', ''), balai_data.get('location', ''),
            balai_data.get('timestamp', ''), balai_token,
            kompetensi_data.get('validator_name', ''), kompetensi_data.get('mac_address', ''), kompetensi_data.get('location', ''),
            kompetensi_data.get('timestamp', ''), kompetensi_token,
            ki_data.get('validator_name', ''), ki_data.get('mac_address', ''), ki_data.get('location', ''),
            ki_data.get('timestamp', ''), ki_token
        ]

        ledger_poa.insert_record('ledger_poa', new_block)
        # print(f"✅ Blok PoA #{block_number} ditambahkan!")
        print(f"✅ Blok PoA #{block_number} ditambahkan! Melalui method proof of authority. Node {node_address}")

        if not args.master:
            # 🔄 **Mulai mining PoW setelah blok PoA ditambahkan**
            pow_thread = threading.Thread(target=start_mining_pow)
            pow_thread.daemon = True
            pow_thread.start()

        # 🔄 **Broadcast hanya blok terbaru**
        broadcast_new_poa_block(new_block)

        return True
    except Exception as e:
        print(f"❌ ERROR: Gagal menambahkan block ke ledger_poa: {str(e)}")
        return False

def proof_of_work(block_data):
    nonce = 0
    target_prefix = "0000"

    while True:
        data_string = "".join(str(item) for item in block_data) + str(nonce)
        hash_attempt = hashlib.sha256(data_string.encode()).hexdigest()

        if hash_attempt.startswith(target_prefix):
            return nonce, hash_attempt
        nonce += 1

def check_for_new_pow_block():
    """
    Mengecek apakah sudah ada blok PoW baru yang ditambahkan ke ledger.
    Jika sudah ada, maka mining harus dihentikan.
    """
    local_last_pow = ledger_pow.fetch_last("ledger_pow")
    
    active_nodes_list = active_nodes.fetch_all("active_nodes")
    nodes = [row[0] for row in active_nodes_list]

    for node in nodes:
        if node == node_address:
            continue
        
        try:
            response = requests.get(f"{node}/latest_pow_block")
            if response.status_code == 200:
                remote_last_pow = response.json().get("block")
                if remote_last_pow and local_last_pow and int(remote_last_pow[0]) > int(local_last_pow[0]):
                    return True  # Ada blok baru di node lain
        except requests.exceptions.RequestException:
            pass

    return False  # Tidak ada blok baru

def submit_pow_result_to_master(mined_block):
    try:
        response = requests.post(f"{NODE_MASTER}/submit_pow_result", json={"block": mined_block})
        if response.status_code == 200:
            print("✅ Hasil mining dikirim ke node master")
        else:
            print("❌ Gagal mengirim hasil mining ke master")
    except requests.exceptions.RequestException as e:
        print(f"❌ Gagal koneksi ke node master: {e}")
    
@app.route('/submit_pow_result', methods=['POST'])
def submit_pow_result():
    global pow_selection_timer, last_finalized_time, last_finalized_block_number

    data = request.get_json()
    block = data.get("block")

    if not block or len(block) < 26:
        return jsonify({"message": "Blok tidak lengkap"}), 400

    block_number = int(block[0])

    # Periksa apakah blok ini baru saja difinalisasi
    if block_number == last_finalized_block_number:
        current_time = time.time()
        if current_time - last_finalized_time < 1.0:  # Toleransi 1 detik
            return jsonify({"message": "Blok sudah difinalisasi baru-baru ini"}), 400

    # Jika sudah ada blok dengan number sama dalam buffer, tambahkan hanya jika timestamp lebih kecil
    existing = [b for b in pending_pow_blocks if int(b[0]) == block_number]
    if existing:
        all_blocks = existing + [block]
        all_blocks.sort(key=lambda b: b[-1])  # Sortir berdasarkan timestamp_miner
        best = all_blocks[0]
        pending_pow_blocks[:] = [best]
    else:
        pending_pow_blocks.append(block)

    print(f"🧩 Hasil mining diterima dari {block[24]} untuk blok #{block_number}")

    if pow_selection_timer is None:
        pow_selection_timer = threading.Timer(2.0, select_best_pow_block)
        pow_selection_timer.start()

    return jsonify({"message": "✅ Diterima sementara oleh node master"})

def select_best_pow_block():
    global pow_selection_timer, last_finalized_time, last_finalized_block_number
    pow_selection_timer = None

    if not pending_pow_blocks:
        print("⚠️ Tidak ada blok POW untuk diproses.")
        return

    best_block = sorted(pending_pow_blocks, key=lambda b: b[-1])[0]
    block_number = best_block[0]

    print(f"⏱️ Memilih blok terbaik #{block_number} untuk validasi...")

    active_nodes_list = active_nodes.fetch_all("active_nodes")
    nodes = [row[0] for row in active_nodes_list if row[0] != node_address]

    votes = 0
    for node in nodes:
        try:
            response = requests.post(f"{node}/validate_candidate_block", json={"block": best_block})
            if response.status_code == 200:
                res = response.json()
                if res.get("valid"):
                    votes += 1
        except:
            print(f"❌ Gagal validasi di {node}")

    print(f"✅ {votes} node menyatakan valid dari {len(nodes)}")

    if votes >= (len(nodes) // 2) + 1:
        existing = ledger_pow.fetch_one("ledger_pow", f"number = '{block_number}'")
        if existing:
            print(f"⛔ Blok #{block_number} sudah ada, abaikan penyimpanan")
        else:
            ledger_pow.insert_record("ledger_pow", best_block)
            print(f"✅ Blok #{block_number} disimpan dan dibroadcast ke semua node.")

        for node in nodes:
            try:
                requests.post(f"{node}/finalize_pow_block", json={"block": best_block})
            except:
                print(f"⚠️ Gagal kirim finalisasi ke {node}")

        # Catat waktu dan nomor blok yang baru saja difinalisasi
        last_finalized_time = time.time()
        last_finalized_block_number = block_number
    else:
        print("❌ Gagal mencapai mayoritas, blok tidak disimpan.")

    pending_pow_blocks.clear()

@app.route('/validate_candidate_block', methods=['POST'])
def validate_candidate_block():
    """
    Endpoint untuk menerima blok kandidat dari master dan memberikan validasi.
    """
    data = request.get_json()
    block = data.get("block")

    try:
        if not block or len(block) < 26:
            return jsonify({"valid": False})

        nonce = block[4]
        block_data = block[0:1] + block[2:4] + block[5:]  # Skip current_block[1] (hash) dan current_block[1] (nonce)
        data_string = "".join(str(item) for item in block_data) + str(nonce)
        recalculated_hash = hashlib.sha256(data_string.encode()).hexdigest()

        if recalculated_hash != block[1] or not recalculated_hash.startswith("0000"):
            return jsonify({"valid": False})

        # Validasi poa_hash
        poa_block = ledger_poa.fetch_one("ledger_poa", f"number = '{block[0]}'")
        if not poa_block or poa_block[1] != block[3]:
            return jsonify({"valid": False})

        print(f"✅ NODE {node_address} menyatakan blok-{block[0]} pada pow ledger valid")
        return jsonify({"valid": True})

    except:
        return jsonify({"valid": False})

@app.route('/finalize_pow_block', methods=['POST'])
def finalize_pow_block():
    """
    Endpoint untuk menerima blok final dari master dan menyimpannya.
    """
    data = request.get_json()
    block = data.get("block")

    try:
        existing = ledger_pow.fetch_one("ledger_pow", f"number = '{block[0]}'")
        if existing:
            print(f"⛔ Blok #{block[0]} sudah ada, abaikan finalisasi")
            return jsonify({"message": "Sudah ada"})

        ledger_pow.insert_record("ledger_pow", block)
        print(f"✅ Blok #{block[0]} ditambahkan dari finalisasi master")
        return jsonify({"message": "Disimpan"})

    except:
        return jsonify({"message": "Gagal simpan"})

def start_mining_pow():
    """
    Memulai proses mining PoW setelah mendapatkan ledger PoA terbaru.
    Jika menemukan blok baru, mengirim hasil mining ke seluruh node untuk validasi.
    """
    global mining_in_progress

    if mining_in_progress:
        print("⛔ Mining sudah berjalan, abaikan permintaan.")
        return
    
    
    # 🚨 **Cek apakah sudah ada blok PoW baru sebelum mulai mining**
    if check_for_new_pow_block():
        print("⚠️ Blok PoW baru sudah ada, menghentikan mining.")
        mining_in_progress = False
        return

    mining_in_progress = True

    print("⛏️ Memulai mining PoW...")

    last_pow_block = ledger_pow.fetch_last("ledger_pow")
    previous_pow_hash = last_pow_block[1] if last_pow_block else "0" * 64
    last_poa_block = ledger_poa.fetch_last("ledger_poa")
    time_mining=datetime.now(timezone.utc).isoformat()

    if last_poa_block:
        block_data = [
            last_poa_block[0], previous_pow_hash, last_poa_block[1],
            last_poa_block[3],  # Project Name
            last_poa_block[4],  # Document Name
            last_poa_block[5],  # Document ID
            last_poa_block[6],  # Document Hash
            last_poa_block[7],  # Balai Validator Name
            last_poa_block[8],  # Balai MAC
            last_poa_block[9],  # Balai Location
            last_poa_block[10], # Balai Timestamp
            last_poa_block[11], # Balai Token
            last_poa_block[12], # Kompetensi Validator Name
            last_poa_block[13], # Kompetensi MAC
            last_poa_block[14], # Kompetensi Location
            last_poa_block[15], # Kompetensi Timestamp
            last_poa_block[16], # Kompetensi Token
            last_poa_block[17], # KI Validator Name
            last_poa_block[18], # KI MAC
            last_poa_block[19], # KI Location
            last_poa_block[20], # KI Timestamp
            last_poa_block[21], # KI Token
            node_address,  # Miner
            time_mining  #Mining Timestamp
        ]        
        nonce, pow_block_hash = proof_of_work(block_data) #proof_of_work Search Nonce and block hash

        new_pow_block = [
            last_poa_block[0],  # Block Number
            pow_block_hash,  # Hash hasil mining
            previous_pow_hash,  # Previous Hash
            last_poa_block[1],  # PoA Hash
            nonce,  # Nonce hasil mining
            last_poa_block[3],  # Project Name
            last_poa_block[4],  # Document Name
            last_poa_block[5],  # Document ID
            last_poa_block[6],  # Document Hash
            last_poa_block[7],  # Balai Validator Name
            last_poa_block[8],  # Balai MAC
            last_poa_block[9],  # Balai Location
            last_poa_block[10], # Balai Timestamp
            last_poa_block[11], # Balai Token
            last_poa_block[12], # Kompetensi Validator Name
            last_poa_block[13], # Kompetensi MAC
            last_poa_block[14], # Kompetensi Location
            last_poa_block[15], # Kompetensi Timestamp
            last_poa_block[16], # Kompetensi Token
            last_poa_block[17], # KI Validator Name
            last_poa_block[18], # KI MAC
            last_poa_block[19], # KI Location
            last_poa_block[20], # KI Timestamp
            last_poa_block[21], # KI Token
            node_address,  # Miner
            time_mining  #Mining Timestamp
        ]

        # 🚨 **Cek ulang apakah ada blok PoW sebelum menyimpan**
        if check_for_new_pow_block():
            print("⚠️ Blok PoW baru ditemukan di jaringan, menghentikan penyimpanan.")
            mining_in_progress = False
            return
        
        if is_valid_ledger('pow'):
            # ✅ **Langsung tambahkan blok PoW ke ledger_pow sendiri**
            mining_in_progress = False
            submit_pow_result_to_master(new_pow_block)
        else:
            print("Blok PoW sudah ada atau tidak valid.")
            return

@app.route('/update_pow_ledger', methods=['POST'])
def update_pow_ledger():
    """
    Menerima ledger PoW terbaru dari node miner dan memperbarui ledger lokal.
    """
    data = request.get_json()
    new_ledger = data.get("ledger", [])

    if not new_ledger:
        return jsonify({"message": "Ledger PoW kosong"}), 400

    # 🔍 **Ambil blok terakhir dari ledger_pow**
    last_pow_block = ledger_pow.fetch_last("ledger_pow")
    last_block_number = int(last_pow_block[0]) if last_pow_block else 0

    # 🚀 **Tambahkan hanya blok yang lebih baru**
    new_blocks_added = 0
    for block in new_ledger:
        block_number = int(block[0])

        if block_number > last_block_number:
            ledger_pow.insert_record("ledger_pow", block)
            new_blocks_added += 1

    print(f"✅ Ledger PoW diperbarui, {new_blocks_added} blok baru ditambahkan.")

    # 🔄 **Validasi ledger setelah pembaruan**
    if not is_valid_ledger('pow'):
        print("❌ Ledger PoW menjadi tidak valid setelah sinkronisasi! Mencari ledger yang valid...")
        longest_valid_ledger = find_longest_valid_ledger('pow')
        if longest_valid_ledger:
            replace_ledger(longest_valid_ledger, 'pow')
            print("✅ Ledger PoW berhasil diganti dengan versi yang valid.")
        else:
            print("⚠️ Tidak ditemukan ledger PoW yang valid di jaringan.")

    return jsonify({"message": f"{new_blocks_added} blok baru ditambahkan ke ledger PoW"}), 200

@app.route('/latest_pow_block', methods=['GET'])
@is_logged_in
def latest_pow_block():
    """
    Mengirimkan blok PoW terbaru yang ada di ledger.
    """
    last_pow_block = ledger_pow.fetch_last("ledger_pow")
    return jsonify({"block": last_pow_block}) if last_pow_block else jsonify({"block": None})

def synchronize_ledger():
    """
    Sinkronisasi ledger PoA & PoW dengan node lain yang terdaftar di active_nodes.db.
    """

    # Ambil daftar node aktif dari database
    active_nodes_list = active_nodes.fetch_all("active_nodes")
    nodes = {row[0] for row in active_nodes_list}  # Set untuk mencegah duplikasi

    if not nodes:
        print("⚠️ Tidak ada node lain yang terdaftar untuk sinkronisasi.")
        return False

    for node in nodes:
        if node == node_address:  # Lewati diri sendiri
            continue

        # 🔄 **Sinkronisasi panjang ledger**
        try:
            # 🔹 Ambil ledger PoA dari node lain
            response_poa = requests.get(f"{node}/poa_chain", timeout=10)
            # 🔹 Ambil ledger PoW dari node lain
            response_pow = requests.get(f"{node}/pow_chain", timeout=10)
            if response_poa.status_code == 200:
                poa_data = response_poa.json()["chain"]
                sync_ledger_poa(poa_data)  # Sinkronisasi panjang ledger PoA
                
            if response_pow.status_code == 200:
                pow_data = response_pow.json()["chain"]
                sync_ledger_pow(pow_data)  # Sinkronisasi panjang ledger PoW

            print(f"✅ Singkronisasi dengan {node} berhasil!!! Panjang ledger sesuai.")

        except requests.exceptions.RequestException:
            print(f"⚠️ Gagal sinkronisasi dengan {node}, node mungkin offline.")

    # 🔄 **Validasi ledger setelah sinkronisasi**
    if not is_valid_ledger('poa'):
        print("❌ Ledger PoA tidak valid setelah sinkronisasi! Mencari ledger yang valid...")
        longest_valid_poa = find_longest_valid_ledger('poa')
        if longest_valid_poa:
            replace_ledger(longest_valid_poa, 'poa')
            print("✅ Ledger PoA berhasil diganti dengan versi yang valid.")
        else:
            print("⚠️ Tidak ditemukan ledger PoA yang valid di jaringan.")

    if not is_valid_ledger('pow'):
        print("❌ Ledger PoW tidak valid setelah sinkronisasi! Mencari ledger yang valid...")
        longest_valid_pow = find_longest_valid_ledger('pow')
        if longest_valid_pow:
            replace_ledger(longest_valid_pow, 'pow')
            print("✅ Ledger PoW berhasil diganti dengan versi yang valid.")
        else:
            print("⚠️ Tidak ditemukan ledger PoW yang valid di jaringan.")

    print("✅ Sinkronisasi Ledger PoA & PoW selesai!")

def sync_ledger_poa(poa_data):
    """
    Memperbarui ledger_poa jika ada blok yang lebih baru.
    """
    last_block_poa = ledger_poa.fetch_last("ledger_poa")
    last_index_poa = int(last_block_poa[0]) if last_block_poa else 0
    last_block_hash = last_block_poa[1] if last_block_poa else "0" * 64  # Genesis hash

    for block in poa_data:
        # Periksa apakah block bertipe dictionary atau tuple/list
        if not isinstance(block, (list, tuple)):
            print(f"❌ ERROR: Format blok tidak dikenali: {block}")
            continue
        
        block_number = int(block[0])

        if block_number > last_index_poa:
            # 🔹 **Validasi previous_hash**
            if block[2] != last_block_hash:
                print(f"❌ ERROR: Previous hash tidak cocok untuk blok #{block_number}. Sinkronisasi dihentikan!")
                return

            ledger_poa.insert_record("ledger_poa", block)
            last_block_hash = block[1]  # Update hash terakhir

            print("✅ Ledger PoA diperbarui!")
    print("✅ sync_ledger_poa selesai!")

def sync_ledger_pow(pow_data):
    """
    Memperbarui ledger_pow jika ada blok yang lebih baru.
    """
    last_block_pow = ledger_pow.fetch_last("ledger_pow")
    last_index_pow = int(last_block_pow[0]) if last_block_pow else 0
    last_block_hash = last_block_pow[1] if last_block_pow else "0" * 64  # Genesis hash

    for block in pow_data:
        # Periksa apakah block bertipe dictionary atau tuple/list
        if isinstance(block, (list, tuple)):  
            block_number = int(block[0])  # Ambil index 0 sebagai number
        else:
            print(f"❌ ERROR: Format blok tidak dikenali: {block}")
            continue
        
        if block_number > last_index_pow:
            # 🔹 **Validasi previous_hash**
            if block[2] != last_block_hash:
                print(f"❌ ERROR: Previous hash tidak cocok untuk blok #{block_number}. Sinkronisasi dihentikan!")
                return

            # 🔹 **Validasi hash PoW**
            block_data = block[0:1] + block[2:4] + block[5:]  # Ambil seluruh isi blok kecuali hash (idx 1) dan nonce (idx 4)
            nonce = block[4]
            data_string = "".join(str(item) for item in block_data) + str(nonce)
            recalculated_hash = hashlib.sha256(data_string.encode()).hexdigest()
            if recalculated_hash != block[1] or not recalculated_hash.startswith("0000"):
                print(f"❌ ERROR: Hash tidak valid untuk blok #{block_number}. Sinkronisasi dihentikan!")
                return
            
            ledger_pow.insert_record("ledger_pow", block)
            last_block_hash = block[1]  # Update hash terakhir

            print("✅ Ledger PoW diperbarui!")
    print("✅ sync_ledger_pow selesai!")

@app.route('/poa_chain', methods=['GET'])
def poa_chain():
    chain=ledger_poa.fetch_all('ledger_poa')
    response = {
        'chain': chain,
        'length': len(chain),
    }
    return jsonify(response), 200

@app.route('/pow_chain', methods=['GET'])
def pow_chain():
    chain=ledger_poa.fetch_all('ledger_pow')
    response = {
        'chain': chain,
        'length': len(chain),
    }
    return jsonify(response), 200
#=====================================================================================================================================
#============================================   POA POW METHOD   =====================================================================
#=====================================================================================================================================

#=====================================================================================================================================
#============================================   START METHOD NODE SETTING   ==========================================================
#=====================================================================================================================================
def register_with_master(node_address):
    """
    Method untuk mendaftarkan node saat ini ke node master.
    """
    payload = {
        "nodes": [node_address]
    }

    try:
        response = requests.post(f"{NODE_MASTER}/nodes/register", json=payload)
        if response.status_code == 201:
            response_data = response.json()
            if "total_nodes" not in response_data or not isinstance(response_data["total_nodes"], list):
                print("⚠️ Response dari node master tidak valid, daftar node tidak ditemukan!")
                return False

            print(f"Berhasil terdaftar ke node master: {NODE_MASTER}")
            print(f"Daftar node yang terdaftar: {response.json()['total_nodes']}")
                
            # Update daftar node di node slave
            active_nodes.delete("active_nodes", "1=1")  # Hapus daftar lama
            for node in response.json()['total_nodes']:
                active_nodes.insert_record("active_nodes", [node])  # Tambahkan node baru
            return True
        else:
            print(f"Gagal terdaftar ke node master. Kode status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Tidak dapat terhubung ke node master: {e}")

    print("❌ Registrasi ke node master gagal.")
    return False    

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        active_nodes.insert_record('active_nodes', [node])
        # blockchain.register_node(node)
    
    # Ambil daftar node aktif terbaru dari database
    active_nodes_list = active_nodes.fetch_all("active_nodes")
    nodes = [row[0] for row in active_nodes_list]

    # Bagikan daftar node aktif ke semua node yang terdaftar
    for node in nodes:
        try:
            url = f"{node}/nodes/update"
            logger.info(f"Mengirim daftar node ke URL: {url}")
            requests.post(url, json={"nodes": nodes})
        except requests.exceptions.RequestException as e:
            print(f"Tidak dapat mengirim daftar node ke {node}: {e}")

    response = {
        'message': 'New nodes have been added',
        'total_nodes': nodes,
    }
    return jsonify(response), 201

@app.route('/nodes/update', methods=['POST'])
def update_nodes():
    # global last_nodes_hash  # Variabel global untuk menyimpan hash daftar node terakhir

    data = request.get_json()
    node_addresses = data.get("nodes")

    if not node_addresses:
        return jsonify({"message": "Daftar node kosong"}), 400

    # 🔹 Simpan daftar node yang diterima ke database
    active_nodes.clear_table("active_nodes")  # Hapus daftar lama
    print("✅ Semua daftar Node lama di hapus.")
    for node in node_addresses:
        active_nodes.insert_record("active_nodes", [node])  # Tambahkan node baru

    print("✅ Daftar node diperbarui.")
    return jsonify({"message": "Daftar node berhasil diperbarui"}), 200

@app.route('/nodes/remove', methods=['POST'])
def remove_node():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid node address", 400

    # Hapus node dari daftar node aktif
    active_nodes.delete("active_nodes", f"node_address = '{node}'")

    # Ambil daftar node aktif terbaru dari database
    active_nodes_list = active_nodes.fetch_all("active_nodes")
    nodes = [row[0] for row in active_nodes_list]

    # Bagikan daftar node aktif yang diperbarui ke semua node yang terdaftar
    for node in nodes:
        try:
            url = f"{node}/nodes/update"
            logger.info(f"Mengirim daftar node ke URL: {url}")
            requests.post(url, json={"nodes": nodes})
        except requests.exceptions.RequestException as e:
            print(f"Tidak dapat mengirim daftar node ke {node}: {e}")

    return jsonify({'message': 'Node berhasil dihapus dari jaringan'}), 200
#=====================================================================================================================================
#=================================================   END METHOD NODE SETTING   =======================================================
#=====================================================================================================================================

#=====================================================================================================================================
#=====================================================   START END-POINT   ===========================================================
#=====================================================================================================================================
@app.route("/upload_document", methods=['GET', 'POST'])
@is_logged_in
def upload_document():
    return render_template('upload_document.html', session=session, page='dashboard')

@app.route("/document_upload_process", methods=['POST'])
@is_logged_in
def document_upload_process():
    print(f"🔄 Masuk method document_upload_process")
    if 'document' not in request.files:
        return 'No file part'
    document = request.files['document']
    if document.filename == '':
        return 'No selected file'
    if document:
        # Ambil data dari session dan form
        uploader = session.get('name')
        project_name = request.form['projectName']
        document_name = request.form['documentName']

        # Generate hash of the file
        document_hash = sha256(document.read()).hexdigest()

        # Reset file cursor position to beginning after reading for hash
        document.seek(0)

        # Cek apakah dokumen sudah ada berdasarkan hash pada 2 collection sekaligus
        status = check_document_status(document_hash)
        if status == 'valid':
            flash("Dokumen sudah pernah diajukan validasi dengan hasil VALID.", "info")
            return redirect(url_for('upload_document'))
        elif status == 'invalid':
            flash("Dokumen sudah pernah diajukan validasi dengan hasil TIDAK VALID.", "warning")
            return redirect(url_for('upload_document'))
        elif status == 'in_progress':
            flash("Dokumen sedang dalam proses validasi.", "info")
            return redirect(url_for('upload_document'))
        
        # Simpan file ke MongoDB GridFS
        client = MongoClient(mongo_server)
        db = client[mongodb_name]
        document_id = GridFS(db).put(document, uploader=uploader, project_name=project_name, 
                                     document_name=document_name, document_hash=document_hash)

        # Simpan metadata dokumen ke koleksi MongoDB
        blockval_mongodb.insert_data('documents', {
                'uploader' : uploader,
                'project_name' : project_name,
                'document_name' : document_name+' '+project_name,
                'document_hash' : document_hash,
                'document_id' : document_id,
                'balai_token' : '',
                'kompetensi_token' : '',
                'ki_token' : '',
                'isValid': 'none'
            })

        return redirect(url_for('dashboard'))

@app.route('/document_management')
@is_logged_in
def document_management():
    try:
        # Hanya uploader yang bisa mengakses halaman ini
        if session['role'] != 'uploader':
            flash("Anda tidak memiliki akses ke halaman ini.", "danger")
            return redirect(url_for('dashboard'))

        uploader_name = session['name']  # Nama user sebagai uploader
        # print(f"Dokumen dari: {uploader_name}")
        
        # Ambil dokumen yang diunggah oleh uploader saat ini
        documents = list(blockval_mongodb.find_data_list('documents', {'uploader': uploader_name}))

        valid_docs = list(blockval_mongodb.find_data_list('valid_docs', {'uploader': uploader_name}))

        return render_template('document_management.html', documents=documents, valid_docs=valid_docs)

    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        flash("Terjadi kesalahan saat memuat halaman kelola dokumen.", "danger")
        return redirect(url_for('dashboard'))


@app.route('/validasi_dokumen', methods=['GET', 'POST'])
@is_logged_in
def validasi_dokumen():
    try:
        # Hanya validator yang bisa mengakses halaman ini
        if session['role'] not in ['validator ki', 'validator balai', 'validator kompetensi']:
            flash("Anda tidak memiliki akses ke halaman ini.", "danger")
            return redirect(url_for('dashboard'))

        documents = blockval_mongodb.get_all_data_dsc('documents', sort_field='_id')
        users = {user['full_name']: user for user in blockval_mongodb.get_all_data('users')}

        # Tambahkan informasi instansi uploader ke dokumen
        for document in documents:
            uploader_name = document.get('uploader', '')
            document['instansi'] = users.get(uploader_name, {}).get('instansi', 'Tidak Diketahui')

        return render_template('validation_page.html', documents=documents)

    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        flash("Terjadi kesalahan saat memuat halaman validasi dokumen.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/view/<file_id>')
@is_logged_in
def view_file(file_id):
    """Menampilkan file di browser tanpa mengunduh"""
    try:
        # Konversi file_id dari string ke ObjectId
        client = MongoClient(mongo_server)
        db = client[mongodb_name]
        file_data = GridFS(db).get(ObjectId(file_id))  # Ambil file dari GridFS
        return send_file(io.BytesIO(file_data.read()), download_name="download.pdf")
    except Exception as e:
        return str(e), 404
    
@app.route('/validate/<file_id>', methods=['POST'])
@is_logged_in
def validate_doc(file_id):
    try:
        user_role = session.get('role')
        allowed_validators = ['validator ki', 'validator balai', 'validator kompetensi']

        if user_role not in allowed_validators:
            flash("Anda tidak memiliki izin untuk memvalidasi dokumen.", "danger")
            return redirect(url_for('validasi_dokumen'))

        status = request.form.get('status')  # Ambil pilihan validasi
        validator_name = session.get('name')

        document = blockval_mongodb.find_data('documents', {'document_id': ObjectId(file_id)})
        if not document:
            flash("Dokumen tidak ditemukan.", "danger")
            return redirect(url_for('validasi_dokumen'))

        mac_address = get_primary_mac_address()
        timestamp = datetime.now(timezone.utc).isoformat()
        location = get_location()

        token_data = {
            "validator_name": validator_name,
            "mac_address": mac_address,
            "location": location,
            "timestamp": timestamp
        }
        encoded_token = encode_token(token_data) if status == "valid" else "invalid"

        update_field = ''
        if user_role == 'validator ki':
            update_field = 'ki_token'
        elif user_role == 'validator kompetensi':
            update_field = 'kompetensi_token'
        elif user_role == 'validator balai':
            update_field = 'balai_token'

        blockval_mongodb.update_data('documents', {'document_id': ObjectId(file_id)}, {update_field: encoded_token})

        # Cek apakah dokumen sudah divalidasi oleh ketiga validator
        document = blockval_mongodb.find_data('documents', {'document_id': ObjectId(file_id)})
        if document['ki_token'] != '' and document['kompetensi_token'] != '' and document['balai_token'] != '':
            if document['ki_token'] != 'invalid' and document['kompetensi_token'] != 'invalid' and document['balai_token'] != 'invalid':

                if not args.master:
                    flash("⏳ Menunggu giliran validasi... Mohon tunggu beberapa saat.", "info")
                    wait_until_master_idle()

                    granted = False
                    while not granted:
                        try:
                            res = requests.post(f"{NODE_MASTER}/set_validation_status", json={
                                "in_progress": True,
                                "validator": validator_name
                            })
                            if res.status_code == 200:
                                granted = True
                                break
                            else:
                                data = res.json()
                                print(f"⏳ Ditolak, sedang diproses oleh: {data.get('message', '-')}. Coba lagi 2 detik...")
                        except Exception as e:
                            print(f"❌ Gagal meminta validasi: {e}")
                        time.sleep(2)

                    try:
                        if is_valid_ledger('poa'):
                            if proof_of_authority(document):
                                flash("Dokumen berhasil divalidasi dan masuk ke blockchain.", "success")
                                print(f"🔄 Node {node_address} berhasil proof_of_authority.")

                                new_doc_id, error = attach_qrcode_to_pdf(document)

                                if error is not None:
                                    flash(f"Gagal menambahkan QR Code: {error}", "danger")
                                    print(f"❌ Node {node_address} Gagal menambahkan QR Code: {error}")
                                    
                                print(f"🔄 Node {node_address} berhasil membuat QRCode.")
                                blockval_mongodb.update_data('documents', {'document_id': ObjectId(file_id)}, {'isValid': 'true'})

                            else:
                                flash("Gagal menambahkan blok PoA.", "danger")
                        else:
                            flash("Ledger PoA tidak valid.", "danger")
                            
                    finally:
                        requests.post(f"{NODE_MASTER}/set_validation_status", json={
                            "in_progress": False,
                            "validator": validator_name
                        })
            else:
                blockval_mongodb.update_data('documents', {'document_id': ObjectId(file_id)}, {'isValid': 'false'})

        return redirect(url_for('validasi_dokumen'))

    except Exception as e:
        return str(e), 500

@app.route('/delete_document/<file_id>', methods=['POST'])
@is_logged_in
def delete_document(file_id):
    try:
        document = blockval_mongodb.find_data('documents', {'document_id': ObjectId(file_id)})

        # Periksa apakah dokumen sudah divalidasi
        if document.get('ki_token') or document.get('kompetensi_token') or document.get('balai_token'):
            flash("Dokumen tidak dapat dihapus karena sudah divalidasi oleh validator.", "danger")
            return redirect(url_for('dashboard'))

        # Hapus dokumen dari MongoDB (GridFS dan metadata)
        client = MongoClient(mongo_server)
        db = client[mongodb_name]
        fs = GridFS(db)
        
        # Hapus dari GridFS
        fs.delete(ObjectId(file_id))
        
        # Hapus metadata dokumen
        blockval_mongodb.delete_data('documents', {'document_id': ObjectId(file_id)})

        flash("Dokumen berhasil dihapus.", "success")
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash(str(e), "danger")
        return redirect(url_for('dashboard'))

@app.route("/account_setting")
@is_logged_in
def account_setting():
    #hanya admin yang bisa mengakses halaman ini
    if session['role'] not in ['admin']:
        flash("Anda tidak memiliki akses ke halaman ini.", "danger")
        return redirect(url_for('dashboard'))
    
    users = blockval_mongodb.get_all_data('users')
    return render_template('account_setting.html', users=users)

@app.route("/user_edit/<user_email>",  methods = ['GET', 'POST'])
@is_logged_in
def user_edit(user_email):
    try:
        user = blockval_mongodb.find_data('users', {"email": user_email})

        if request.method == 'POST': 
            # Ambil nilai baru dari form
            new_jenis_user = request.form['jenis_user']

            # Update nilai 'jenis_user' pada database MongoDB
            blockval_mongodb.update_data('users', {'email': user_email}, {'jenis_user': new_jenis_user})
            # Redirect ke halaman daftar akun setelah berhasil update
            return redirect(url_for('account_setting'))
        
        return render_template('edit_user_page.html', user=user, session=session)
    
    except Exception as e:
        return str(e), 404

@app.route('/token_decoder', methods = ['GET', 'POST'])
@is_logged_in
def token_decoder():
    return render_template('token_decoder.html', session=session)

@app.route('/decode_process', methods = ['GET', 'POST'])
@is_logged_in
def decode_process():
    decoded_token = ''
    if request.method == 'POST':
        token = request.form['token']
        decoded_token = decode_token(token)

    return render_template('token_decoder.html', session=session, decoded_token = decoded_token)

@app.route("/manual_sync", methods=["POST"])
@is_logged_in
def manual_sync():
    try:
        log_capture = io.StringIO()
        sys_stdout = sys.stdout
        sys.stdout = log_capture

        synchronize_ledger()  # Panggil fungsi sinkronisasi

        sys.stdout = sys_stdout
        log_result = log_capture.getvalue().splitlines()

        return jsonify({"message": "✅ Sinkronisasi berhasil!", "log": log_result})
    except Exception as e:
        return jsonify({"message": f"❌ Gagal sinkronisasi: {str(e)}", "log": []}), 500


@app.route("/register", methods = ['GET', 'POST'])
def register():
    if 'blockval_logged_in' in session and session['blockval_logged_in']:
        return redirect(url_for('dashboard'))

    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():
        username = form.username.data
        name = form.name.data
        email = form.email.data
        instansi = form.instansi.data

        if blockval_mongodb.is_new('users',email=email):
            password = sha256_crypt.hash(form.password.data)
            blockval_mongodb.insert_data('users', {
                'full_name' : name,
                'username' : username,
                'instansi' : instansi,
                'email' : email,
                'password' : password,
                'jenis_user' : ''
            })
            log_in_user(username)
            return redirect(url_for('dashboard'))
        else:
            flash('User already exists', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

@app.route("/login", methods = ['GET', 'POST'])
def login():
    if 'blockval_logged_in' in session and session['blockval_logged_in']:
        return redirect(url_for('dashboard'))

    form = LoginForm(request.form)

    if request.method == 'POST':
        # username = request.form['username']
        # candidatepass = request.form['password']
        username = form.username.data
        candidatepass = form.password.data

        user = blockval_mongodb.find_data('users', {'username': username})
        accpass = user.get('password')

        if accpass is None:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        else:
            if sha256_crypt.verify(candidatepass, accpass):
                log_in_user(username)
                flash('You are now Logged in.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password.', 'danger')
                return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash('Logout Success.', 'success')
    return redirect(url_for('login'))

@app.route("/dashboard")
@is_logged_in
def dashboard():
    try:
        # Ambil semua dokumen dari koleksi `documents`
        documents = blockval_mongodb.get_all_data('documents')

        # Ambil daftar semua pengguna dari koleksi `users`
        users = {user['full_name']: user for user in blockval_mongodb.get_all_data('users')}

        # Gabungkan informasi uploader dengan instansi dari users
        for document in documents:
            uploader_email = document.get('uploader', '')
            document['instansi'] = users.get(uploader_email, {}).get('instansi', 'Tidak Diketahui')

        return render_template('dashboard.html', documents=documents)

    except Exception as e:
        flash(str(e), "danger")
        return redirect(url_for('logout'))

@app.route("/", methods = ['GET', 'POST'])
def index():
    if 'blockval_logged_in' in session and session['blockval_logged_in']:
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))

#=====================================================================================================================================
#=====================================================   END END-POINT   =============================================================
#=====================================================================================================================================


if __name__ == '__main__':
    app.secret_key = 'secret123'

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-a', '--address', default=None, help='alamat node (contoh: http://192.168.1.40:5000)')
    parser.add_argument('--master', action='store_true', help='jalankan sebagai node master')
    args = parser.parse_args()

    port = args.port    

    # Jika --address tidak disertakan, gunakan alamat default
    if args.address is None:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        node_address = f"http://{ip_address}:{port}"
    else:
        node_address = args.address

    # Jika node master, daftarkan dirinya sendiri ke daftar node
    if args.master:
        active_nodes.insert_record("active_nodes", [node_address])
        print("Menjalankan sebagai node master. Node master terdaftar.")
    else:
        # Jika bukan node master, daftarkan ke node master
        print("Mendaftarkan node ke node master...")
        register_with_master(node_address)
    
    # Daftarkan handler saat program dimatikan
    atexit.register(shutdown_handler)

    synchronize_ledger()

    # Jalankan Flask app
    app.run(host='0.0.0.0', port=port, threaded=True)