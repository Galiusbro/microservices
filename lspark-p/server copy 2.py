import base64
from email import errors
from flask import Flask, json, jsonify, request
import jwt
import requests
from functools import wraps
from pymongo import MongoClient
import os
import subprocess
import uuid
from flask_cors import CORS
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidTokenError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from bson import ObjectId
import uma
import traceback
# Инициализация Flask и MongoDB клиента
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Добавляем поддержку CORS для всех доменов
DATABASE_URL = "mongodb+srv://ayaalsantaev:rMYFtEKsAU5RkMIw@cluster-v2.p0dfs.mongodb.net/test?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true"
client = MongoClient(DATABASE_URL)
db = client.test
keys_collection = db.keys
keys_collection.create_index("user_id", unique=True)

# Настройки для JWT
AUTH0_DOMAIN = "dev-w4mhfi5sg7rm3bcl.us.auth0.com"
API_IDENTIFIER = "http://localhost:3033"
ALGORITHMS = ["RS256"]

# Функция для конвертации JWKS в PEM
def get_rsa_key(jwks, kid):
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == kid:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
            break
    if rsa_key:
        return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(rsa_key))
    return None

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

        rsa_key = get_rsa_key(jwks, unverified_header["kid"])
        
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer=f"https://{AUTH0_DOMAIN}/"
                )
            except ExpiredSignatureError:
                return jsonify({"message": "Token is expired"}), 401
            except InvalidAudienceError:
                return jsonify({"message": "Incorrect claims, please check the audience and issuer"}), 401
            except InvalidTokenError:
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
        existing_keys["_id"] = str(existing_keys["_id"])
        return jsonify({"message": "Keys already exist for this user", "keys": existing_keys}), 200

    # Генерация ключей, если они отсутствуют
    key_file = f'ec_key_{uuid.uuid4().hex}.pem'
    cert_file = f'ec_crt_{uuid.uuid4().hex}.crt'

    try:
        # Генерация secp256k1 ключа
        subprocess.run(['openssl', 'ecparam', '-genkey', '-name', 'secp256k1', '-out', key_file], check=True)

        # Получение публичного ключа
        result = subprocess.run(['openssl', 'ec', '-in', key_file, '-pubout', '-outform', 'DER'], check=True, capture_output=True)
        # public_key_der = result.stdout
        public_key = result.stdout
        # public_key_base64 = base64.b64encode(public_key_der).decode('utf-8')

        # Создание самоподписанного сертификата
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-key', key_file,
            '-sha256', '-nodes', '-out', cert_file,
            '-days', '365',
            '-subj', '/C=AS/ST=AS/L=AS/O=AS/OU=AS/CN=AS/emailAddress=galprimulus@gmail.com'
        ], check=True)

        # Считывание содержимого сертификата
        with open(cert_file, 'rb') as cert:
            cert_data = base64.b64encode(cert.read()).decode('utf-8')

        # Сохранение публичного ключа и сертификата в базе данных MongoDB с user_id
        keys_data = {
            "user_id": user_id,
            "public_key": public_key,
            "certificate": cert_data
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

# Обновленная функция для форматирования данных ключей
def format_keys(keys):
    return {
        "_id": str(keys.get("_id", "")),
        "user_id": keys["user_id"],
        "public_key": base64.b64encode(keys["public_key"]).decode('utf-8'),  # Convert bytes to base64 string
        "certificate": keys["certificate"]
    }

# Маршрут для начального LNURLp запроса
@app.route('/initial_lnurlp_request', methods=['POST'])
@requires_auth  # Требуется аутентификация JWT
def initial_lnurlp_request():
    user_id = request.user["sub"]  # Получение user_id из JWT токена

    # Извлечение ключей пользователя из базы данных
    user_keys = keys_collection.find_one({"user_id": user_id})
    if not user_keys:
        return jsonify({"message": "Keys not found for this user"}), 404

    # Извлечение данных для формирования запроса
    public_key = user_keys["public_key"]
    certificate = user_keys["certificate"]

    try:
        # Создание начального LNURLp запроса используя Lightspark UMA SDK
        lnurlp_request = uma.create_uma_lnurlp_request_url(
        signing_private_key=base64.b64decode(public_key),
        receiver_address="$bob@vasp2.com",
        sender_vasp_domain="vasp1.com",
        is_subject_to_travel_rule=True,
    )

        return jsonify({"message": "LNURLp request created successfully", "lnurlp": lnurlp_request}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Пример защищенного маршрута
@app.route('/protected', methods=['GET'])
@requires_auth  # Требуется аутентификация JWT
def protected():
    user_id = request.user["sub"]
    return jsonify(logged_in_as=user_id), 200

if __name__ == '__main__':
    app.run(debug=True)