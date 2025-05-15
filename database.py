import json
import os
import sqlite3

def init_db():
    """
    Inisialisasi database dan buat tabel jika belum ada.
    """
    db_path = 'blockchain.db'
    print(f"Membuat atau membuka database di: {os.path.abspath(db_path)}", flush=True)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Buat tabel transactions jika belum ada
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (sender text, recipient text, amount real)''')
    
    # Buat tabel blocks jika belum ada
    c.execute('''CREATE TABLE IF NOT EXISTS blocks
                 ("index" integer, timestamp real, transactions text, proof integer, previous_hash text)''')
    
    # Buat tabel nodes jika belum ada
    c.execute('''CREATE TABLE IF NOT EXISTS nodes
                 (address text PRIMARY KEY)''')  # Tabel untuk menyimpan daftar node
    
    conn.commit()
    conn.close()

def save_transaction(sender, recipient, amount):
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    c.execute("INSERT INTO transactions VALUES (?, ?, ?)", (sender, recipient, amount))
    conn.commit()
    conn.close()

def save_block(block):
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)", 
              (block['index'], block['timestamp'], json.dumps(block['transactions']), block['proof'], block['previous_hash']))
    conn.commit()
    conn.close()

def save_node(address):
    """
    Menyimpan alamat node ke database.
    """
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO nodes VALUES (?)", (address,))
    conn.commit()
    conn.close()

def load_nodesss():
    """
    Memuat daftar node dari database.
    """
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    c.execute("SELECT address FROM nodes")
    nodes = [row[0] for row in c.fetchall()]
    conn.close()
    return nodes

def delete_node(address):
    """
    Menghapus node dari database.
    """
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    c.execute("DELETE FROM nodes WHERE address = ?", (address,))
    conn.commit()
    conn.close()

def save_chain(chain):
    """
    Menyimpan seluruh chain ke database.
    """
    print("Menyimpan chain ke database...")
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    
    # Hapus data chain lama (jika ada)
    c.execute("DELETE FROM blocks")  # Hapus semua blok yang ada
    print(f"Menghapus {c.rowcount} blok lama dari database.")
    
    # Simpan setiap blok ke database
    for block in chain:
        c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)", 
                  (block['index'], block['timestamp'], json.dumps(block['transactions']), block['proof'], block['previous_hash']))
        print(f"Blok {block['index']} disimpan ke database.")

    conn.commit()
    conn.close()

def load_chain():
    """
    Memuat seluruh chain dari database.
    """
    print("Memuat chain dari database...")
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM blocks ORDER BY 'index' ASC")
    rows = c.fetchall()
    
    chain = []
    for row in rows:
        block = {
            'index': row[0],
            'timestamp': row[1],
            'transactions': json.loads(row[2]),
            'proof': row[3],
            'previous_hash': row[4],
        }
        chain.append(block)
        print(f"Blok {block['index']} dimuat dari database.")
    
    conn.close()
    print(f"Chain berhasil dimuat. Jumlah blok: {len(chain)}")
    return chain