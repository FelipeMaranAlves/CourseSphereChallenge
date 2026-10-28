import os
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from query_manager import QueryManager
from firebase import Firebase
from main import hashFunction
from blueprints.courses import courses_bp

app = Flask(__name__)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000",
    ).split(",")
    if origin.strip()
]
CORS(app, resources={r"/*": {"origins": allowed_origins}})

app.register_blueprint(courses_bp)

success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({'error': error}), code)


def extract_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    if isinstance(auth_header, str) and auth_header.startswith("Bearer "):
        token = auth_header.split("Bearer ", 1)[1].strip()
        if token:
            return token
    return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        id_token = extract_bearer_token()
        if not id_token:
            return error_response("Missing or malformed Authorization Bearer token", 401)
        try:
            decoded = Firebase.verify_id_token(id_token)
            uid = decoded.get("uid") if isinstance(decoded, dict) else None
            if not uid:
                return error_response("Invalid authentication token", 401)
        except Exception as exc:
            app.logger.warning("Token verification failed: %s", exc)
            return error_response("Invalid or expired authentication token", 401)
        return f(uid, *args, **kwargs)
    return decorated


@app.route("/users/create", methods=["POST"])
def create_user():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Invalid JSON payload", 400)
    email = data.get("email")
    password = data.get("password")
    if not email:
        return error_response("Email is required", 400)
    if not password:
        return error_response("Password is required", 400)
    try:
        return success_response(Firebase.create_user(email, password), 200)
    except Exception as e:
        app.logger.error("Error creating user: %s", e)
        return error_response("Error creating user", 400)


@app.route("/users/info", methods=["POST"])
@require_auth
def set_user_info(uid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Invalid JSON payload", 400)
    try:
        user_info = {
            "majors": data.get("majors"),
            "minors": data.get("minors"),
            "courses": data.get("courses"),
            "college": data.get("college"),
            "year": data.get("year"),
            "about": data.get("about"),
        }
        Firebase.set_user_info(uid, user_info)
        return success_response({"message": "User info set successfully", "uid": uid}, 200)
    except Exception as e:
        app.logger.error("Error setting user info for uid %s: %s", uid, e)
        return error_response("Error setting user info", 400)


@app.route("/users/info", methods=["GET"])
@require_auth
def get_user_info(uid):
    try:
        user_info = Firebase.get_user_info(uid)
        return success_response(user_info, 200)
    except Exception as e:
        app.logger.error("Error getting user info for uid %s: %s", uid, e)
        return error_response("Error getting user info", 400)


@app.route("/users/query", methods=["POST"])
@require_auth
def get_user_query(uid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Invalid JSON payload", 400)
    query = data.get("query")
    if not isinstance(query, str) or not query.strip():
        return error_response("Query is required and must be a non-empty string", 400)
    try:
        user_info = Firebase.get_user_info(uid)
        return success_response(QueryManager(query.strip(), user_info).response, 200)
    except Exception as e:
        app.logger.error("Error generating query response for uid %s: %s", uid, e)
        return error_response("Error generating query response", 400)


@app.route('/hash', methods=['POST'])
@require_auth
def generate_message_id(uid):
    try:
        data = request.get_json(silent=True)
        if data is None:
            return error_response("Invalid JSON payload", 400)
        message_id = hashFunction(data)
        return jsonify({'messageID': message_id}), 200
    except Exception as e:
        app.logger.error("Error generating hash for uid %s: %s", uid, e)
        return error_response("Internal server error generating message ID", 500)


@app.route("/chats/<chat_id>/messages", methods=["POST"])
@require_auth
def save_chat(uid, chat_id):
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Invalid JSON payload", 400)
        messages = data.get('messages', [])
        Firebase.save_chat(uid, chat_id, messages)
        return jsonify({'message': 'Messages saved successfully'}), 200
    except Exception as e:
        app.logger.error("Error saving messages for uid %s: %s", uid, e)
        return error_response("Error saving messages", 400)


@app.route("/chats/<chat_id>", methods=["DELETE"])
@require_auth
def delete_chat(uid, chat_id):
    try:
        Firebase.delete_chat(uid, chat_id)
        return success_response({'message': 'Message deleted successfully'}, 200)
    except Exception as e:
        app.logger.error("Error deleting chat for uid %s: %s", uid, e)
        return error_response("Error deleting message", 400)


if __name__ == '__main__':
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug_mode)
