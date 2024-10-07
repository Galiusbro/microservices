from flask import Flask, jsonify, request
import jwt
import requests
from functools import wraps
from pymongo import MongoClient, errors
import os
import subprocess
import uuid
from flask_cors import CORS
import base64

# Инициализация Flask и MongoDB клиента
app = Flask(__name__)
CORS(app)  # Добавляем поддержку CORS
DATABASE_URL = "mongodb+srv://ayaalsantaev:rMYFtEKsAU5RkMIw@cluster-v2.p0dfs.mongodb.net/test?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true"
client = MongoClient(DATABASE_URL)
db = client.test
keys_collection = db.keys

# Создаем уникальный индекс для user_id
keys_collection.create_index("user_id", unique=True)

# Настройки для JWT
AUTH0_DOMAIN = "dev-w4mhfi5sg7rm3bcl.us.auth0.com"
API_IDENTIFIER = "http://localhost:3033"
ALGORITHMS = ["RS256"]

# Функция для проверки JWT
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header:
            return jsonify({"message": "Authorization header is expected"}), 401

        parts = auth_header.split()

        if parts[0].lower() != "bearer":
            return jsonify({"message": "Authorization header must start with Bearer"}), 401
        elif len(parts) == 1:
            return jsonify({"message": "Token not found"}), 401
        elif len(parts) > 2:
            return jsonify({"message": "Authorization header must be Bearer token"}), 401

        token = parts[1]
        jsonurl = requests.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
        jwks = jsonurl.json()
        unverified_header = jwt.get_unverified_header(token)

        rsa_key = {}
        if "kid" not in unverified_header:
            return jsonify({"message": "Authorization malformed"}), 401

        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer=f"https://{AUTH0_DOMAIN}/"
                )
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token is expired"}), 401
            except jwt.JWTClaimsError:
                return jsonify({"message": "Incorrect claims, please check the audience and issuer"}), 401
            except Exception:
                return jsonify({"message": "Unable to parse authentication token"}), 401

            request.user = payload
            return f(*args, **kwargs)

        return jsonify({"message": "Unable to find appropriate key"}), 401

    return decorated

# Маршрут для генерации ключей и их сохранения в базе данных, если они отсутствуют
@app.route('/generate_keys_if_absent', methods=['POST'])
@requires_auth  # Требуется аутентификация JWT
def generate_keys_if_absent():
    user_id = request.user["sub"]  # Получение user_id из JWT токена

    # Проверка, есть ли уже ключи для данного пользователя
    existing_keys = keys_collection.find_one({"user_id": user_id})
    if existing_keys:
        return jsonify({"message": "Keys already exist for this user", "keys": format_keys(existing_keys)}), 200

    # Генерация ключей, если они отсутствуют
    key_file = f'ec_key_{uuid.uuid4().hex}.pem'
    cert_file = f'ec_crt_{uuid.uuid4().hex}.crt'

    try:
        # Генерация secp256k1 ключа
        subprocess.run(['openssl', 'ecparam', '-genkey', '-name', 'secp256k1', '-out', key_file], check=True)

        # Получение публичного ключа
        result = subprocess.run(['openssl', 'ec', '-in', key_file, '-pubout', '-outform', 'DER'], check=True, capture_output=True)
        public_key_der = result.stdout
        public_key_base64 = base64.b64encode(public_key_der).decode('utf-8')

        # Создание самоподписанного сертификата
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-key', key_file,
            '-sha256', '-nodes', '-out', cert_file,
            '-days', '365',
            '-subj', '/C=AS/ST=AS/L=AS/O=AS/OU=AS/CN=AS/emailAddress=galprimulus@gmail.com'
        ], check=True)

        # Сохранение публичного ключа в базе данных MongoDB с user_id
        keys_data = {
            "user_id": user_id,
            "public_key": public_key_base64,
            "cert_file": cert_file,
            "key_file": key_file
        }
        keys_collection.insert_one(keys_data)

        # Удаление файлов с сервера
        os.remove(key_file)
        os.remove(cert_file)

        return jsonify({"message": "Keys generated and stored in database", "keys": format_keys(keys_data)}), 201

    except errors.DuplicateKeyError:
        return jsonify({"message": "Keys already exist for this user"}), 409
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def format_keys(keys):
    return {
        "_id": str(keys.get("_id", "")),
        "user_id": keys["user_id"],
        "cert_file": keys["cert_file"],
        "key_file": keys["key_file"],
        "public_key": keys["public_key"]
    }

# Пример защищенного маршрута
@app.route('/protected', methods=['GET'])
@requires_auth  # Требуется аутентификация JWT
def protected():
    user_id = request.user["sub"]
    return jsonify(logged_in_as=user_id), 200

if __name__ == '__main__':
    app.run(debug=True)
