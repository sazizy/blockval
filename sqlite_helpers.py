import sqlite3


class SQLiteHelper:
    def __init__(self, db_path, table_name, columns):
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self.create_table(table_name, columns)

    def create_table(self, table_name, columns):
        # columns_definition = ", ".join([f"{column} TEXT" for column in columns])
        column_defs = []
        for col in columns:
            if isinstance(col, tuple):
                column_defs.append(f"{col[0]} {col[1]}")
            else:
                column_defs.append(f"{col} TEXT")
        columns_definition = ", ".join(column_defs)
        with self.connection:
            self.connection.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_definition})")

    def insert_record(self, table_name, values):
        placeholders = ", ".join(["?" for _ in values])
        with self.connection:
            self.connection.execute(f"INSERT INTO {table_name} VALUES ({placeholders})", values)

    def update_record(self, table_name, values, condition):
        with self.connection:
            cursor = self.connection.cursor()
            set_clause = ", ".join([f"{column} = ?" for column in values.keys()])
            query = f"UPDATE {table_name} SET {set_clause} WHERE {condition}"
            cursor.execute(query, list(values.values()))
            self.connection.commit()
            cursor.close()

    def fetch_all(self, table_name):
        with self.connection:
            cursor = self.connection.cursor()
            
            # Pastikan hanya ledger yang diurutkan berdasarkan number ASC
            if table_name in ["ledger_poa", "ledger_pow"]:
                query = f"SELECT * FROM {table_name} ORDER BY number ASC"
            else:
                query = f"SELECT * FROM {table_name}"  # Untuk tabel lain tanpa kolom number
            
            cursor.execute(query)
            result = cursor.fetchall()
            cursor.close()
            return result

    def fetch_one(self, table_name, condition):
        with self.connection:
            cursor = self.connection.cursor()
            cursor.execute(f"SELECT * FROM {table_name} WHERE {condition}")
            result = cursor.fetchone()
            cursor.close()
            return result
    
    def fetch_last(self, table_name):
        with self.connection:
            cursor = self.connection.cursor()

            # Pastikan hanya ledger yang diurutkan berdasarkan number DESC
            if table_name in ["ledger_poa", "ledger_pow"]:
                query = f"SELECT * FROM {table_name} ORDER BY number DESC LIMIT 1"
            else:
                query = f"SELECT * FROM {table_name} LIMIT 1"  # Untuk tabel lain tanpa kolom number
            
            cursor.execute(query)
            result = cursor.fetchone()
            cursor.close()
            return result
    
    def delete(self, table_name, condition):
        with self.connection:
            cursor = self.connection.cursor()
            cursor.execute(f"DELETE FROM {table_name} WHERE {condition}")
            self.connection.commit()
            cursor.close()

    def clear_table(self, table_name):
        with self.connection:
            cursor = self.connection.cursor()
            cursor.execute(f"DELETE FROM {table_name}")
            self.connection.commit()
            cursor.close()

    def get_column_names(self, table_name):
        with self.connection:
            cursor = self.connection.cursor()
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = [row[1] for row in cursor.fetchall()]
            cursor.close()
            return columns

    def close_connection(self):
        self.connection.close()
    # def __init__(self, db_path, table_name, columns):
    #     self.connection = sqlite3.connect(db_path, check_same_thread=False)
    #     self.cursor = self.connection.cursor()
    #     self.create_table(table_name, columns)

    # def create_table(self, table_name, columns):
    #     columns_definition = ", ".join([f"{column} TEXT" for column in columns])
    #     self.cursor.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_definition})")
    #     self.connection.commit()

    # def insert_record(self, table_name, values):
    #     placeholders = ", ".join(["?" for _ in values])
    #     self.cursor.execute(f"INSERT INTO {table_name} VALUES ({placeholders})", values)
    #     self.connection.commit()

    # def fetch_all(self, table_name):
    #     self.cursor.execute(f"SELECT * FROM {table_name}")
    #     return self.cursor.fetchall()

    # def fetch_one(self, table_name, condition):
    #     self.cursor.execute(f"SELECT * FROM {table_name} WHERE {condition}")
    #     return self.cursor.fetchone()
    
    # def fetch_last(self, table_name):
    #     self.cursor.execute(f"SELECT * FROM {table_name} ORDER BY number DESC LIMIT 1")
    #     return self.cursor.fetchone()
    
    # def delete(self, table_name, condition):
    #     self.cursor.execute(f"DELETE FROM {table_name} WHERE {condition}")
    #     return self.cursor.fetchone()

    # def clear_table(self, table_name):
    #     self.cursor.execute(f"DELETE FROM {table_name}")
    #     self.connection.commit()
    #     return self.cursor.fetchone()

    # def close_connection(self):
    #     self.connection.close()
