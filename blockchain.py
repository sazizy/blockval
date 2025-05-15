import hashlib
import json
from time import time
from uuid import uuid4
from flask import Flask, jsonify, request
import sqlite3
import requests

from database import load_nodesss, save_node, load_chain, save_chain

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

        # Muat chain dari database jika ada
        self.load_chain()

        # Jika chain kosong, buat blok genesis
        if not self.chain:
            self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        self.current_transactions = []
        self.chain.append(block)

        # Simpan chain ke database
        save_chain(self.chain)
        return block

    def new_transaction(self, sender, recipient, amount):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })
        return self.last_block['index'] + 1

    # def broadcast_block(self, block):
    #     """
    #     Menyebarkan blok baru ke seluruh node dalam jaringan.
    #     """
    #     for node in self.nodes:
    #         try:
    #             url = f"http://{node}/blocks/new"
    #             response = requests.post(url, json=block)
    #             if response.status_code == 201:
    #                 print(f"Blok berhasil disebarkan ke {node}")
    #             else:
    #                 print(f"Gagal menyebarkan blok ke {node}. Kode status: {response.status_code}")
    #         except requests.exceptions.RequestException as e:  # Perbaiki penanganan exception
    #             print(f"Tidak dapat terhubung ke {node}: {e}")

    def load_chain(self):
        """
        Memuat chain dari database.
        """
        self.chain = load_chain()

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def load_nodess(self):
        nodes = load_nodesss()
        for node in nodes:
            self.nodes.add(node)
    
    def register_node(self, address):
        self.nodes.add(address)
        save_node(address) 

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False

            if not self.valid_proof(last_block['proof'], block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.RequestException as e:
                print(f"Tidak dapat terhubung ke {node}: {e}")

        if new_chain:
            self.chain = new_chain
            return True

        return False