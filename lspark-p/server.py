import base64
from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import uma
import traceback
from keys import save_keys, keys_collection
from auth import requires_auth

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Добавляем поддержку CORS для всех доменов

@app.route('/generate_keys_if_absent', methods=['POST'])
@requires_auth  # Требуется аутентификация JWT
def generate_keys_if_absent():
    user_id = request.user["sub"]  # Получение user_id из JWT токена
    response, status_code = save_keys(user_id)
    return jsonify(response), status_code

@app.route('/initial_lnurlp_request', methods=['POST'])
@requires_auth  # Требуется аутентификация JWT
def initial_lnurlp_request():
    user_id = request.user["sub"]  # Получение user_id из JWT токена

    # Извлечение ключей пользователя из базы данных
    user_keys = keys_collection.find_one({"user_id": user_id})
    if not user_keys:
        return jsonify({"message": "Keys not found for this user"}), 404

    # Извлечение данных для формирования запроса
    private_key_der = base64.b64decode(user_keys["private_key"])

    try:
        # Создание начального LNURLp запроса используя Lightspark UMA SDK
        lnurlp_request = uma.create_uma_lnurlp_request_url(
            signing_private_key=private_key_der,
            receiver_address="$bob@vasp2.com",
            sender_vasp_domain="vasp1.com",
            is_subject_to_travel_rule=True,
        )

        # Выполнение запроса к созданному LNURLp
        response = requests.get(lnurlp_request)
        lnurlp_request_parse = uma.parse_lnurlp_request(lnurlp_request)

        print("LNURLp request: ", lnurlp_request_parse)

        # Проверка статуса ответа
        if response.status_code == 200:
            try:
                response_json = response.json()
            except ValueError:
                return jsonify({"message": "LNURLp request completed, but response is not valid JSON", "lnurlp_response": response.text}), 200

            return jsonify({"message": "LNURLp request created successfully", "lnurlp_response": response_json}), 200
        else:
            return jsonify({"message": "Failed to perform LNURLp request", "details": response.text}), response.status_code

    except requests.RequestException as e:
        # Обработка ошибок запроса
        error_message = str(e)
        traceback_str = traceback.format_exc()
        print("Request error occurred: ", error_message)
        print("Traceback: ", traceback_str)

        return jsonify({"error": "Failed to connect to LNURLp endpoint", "details": error_message, "traceback": traceback_str}), 500

    except Exception as e:
        # Общая обработка ошибок
        error_message = str(e)
        traceback_str = traceback.format_exc()
        print("Unexpected error occurred: ", error_message)
        print("Traceback: ", traceback_str)

        return jsonify({"error": "Failed to perform LNURLp request", "details": error_message, "traceback": traceback_str}), 500

@app.route('/protected', methods=['GET'])
@requires_auth  # Требуется аутентификация JWT
def protected():
    user_id = request.user["sub"]
    return jsonify(logged_in_as=user_id), 200

if __name__ == '__main__':
    app.run(debug=True)
