from pymongo import MongoClient, DESCENDING

class MongoDBHelper():
    def __init__(self, uri, db_name):
        self.client = MongoClient(uri)
        self.db = self.client[db_name]

    def get_collection(self, collection_name):
        return self.db[collection_name]

    def insert_data(self, collection_name, document):
        collection = self.get_collection(collection_name)
        collection.insert_one(document)

    def find_data(self, collection_name, query):
        collection = self.get_collection(collection_name)
        return collection.find_one(query)
    
    def find_data_list(self, collection_name, query):
        collection = self.get_collection(collection_name)
        return collection.find(query)

    def update_data(self, collection_name, query, new_values):
        collection = self.get_collection(collection_name)
        collection.update_one(query, {"$set": new_values})

    def delete_data(self, collection_name, query):
        collection = self.get_collection(collection_name)
        collection.delete_one(query)

    def get_all_data(self, collection_name):
        collection = self.get_collection(collection_name)
        return list(collection.find())
    
    def get_all_data_dsc(self, collection_name, sort_field=None):
        collection = self.get_collection(collection_name)
        if sort_field:
            return list(collection.find().sort(sort_field, DESCENDING))
        return list(collection.find())
    
    def is_new(self, collection_name, email):
        collection = self.get_collection(collection_name)
        # Find a document where 'email' matches the input email
        user = collection.find_one({"email": email})
        # Return True if no such user exists, else return False
        return user is None