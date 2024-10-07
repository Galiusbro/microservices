import base64
from coincurve import PrivateKey
from pymongo import MongoClient, errors

DATABASE_URL = "mongodb+srv://ayaalsantaev:rMYFtEKsAU5RkMIw@cluster-v2.p0dfs.mongodb.net/test?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true"
client = MongoClient(DATABASE_URL)
db = client.test
keys_collection = db.keys
keys_collection.create_index("user_id", unique=True)

def generate_secp256k1_key():
    private_key = PrivateKey()
    public_key = private_key.public_key.format(compressed=False)
    public_key_base64 = base64.b64encode(public_key).decode('utf-8')

    private_key_der = private_key.to_der()
    private_key_base64 = base64.b64encode(private_key_der).decode('utf-8')

    return {
        "private_key": private_key_base64,
        "public_key": public_key_base64
    }

def save_keys(user_id):
    # Проверка, есть ли уже ключи для данного пользователя
    existing_keys = keys_collection.find_one({"user_id": user_id})
    if existing_keys:
        return {"message": "Keys already exist for this user", "keys": format_keys(existing_keys)}, 200

    # Генерация ключей, если они отсутствуют
    try:
        keys_data = generate_secp256k1_key()
        keys_data["user_id"] = user_id
        keys_collection.insert_one(keys_data)
        return {"message": "Keys generated and stored in database", "keys": format_keys(keys_data)}, 201

    except errors.DuplicateKeyError:
        return {"message": "Keys already exist for this user"}, 409
    except Exception as e:
        return {"error": str(e)}, 500

def format_keys(keys):
    return {
        "_id": str(keys.get("_id", "")),
        "user_id": keys["user_id"],
        "public_key": keys["public_key"],
        "private_key": "hidden"
    }
