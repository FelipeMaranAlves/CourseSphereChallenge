import logging
import os
from functools import wraps
from flask import Flask, g, request, jsonify
from flask_cors import CORS
from query_manager import QueryManager
from firebase import Firebase
from main import hashFunction
from blueprints.courses import courses_bp
from observability import log_event, metrics, register_observability
from security import (
    apply_security_headers,
    rate_limit,
    sanitize_string_list,
    sanitize_text,
    validate_email_and_password,
    validate_safe_identifier,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # Limit request payload size to 64 KB

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
logger = register_observability(app)

success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({'error': error}), code)


@app.after_request
def set_security_headers(response):
    return apply_security_headers(response)


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
            metrics.record_auth_failure("missing_token")
            log_event(
                logger,
                logging.WARNING,
                "auth_failure",
                "Missing or malformed Authorization Bearer token",
                path=request.path,
                method=request.method,
            )
            return error_response("Missing or malformed Authorization Bearer token", 401)
        try:
            decoded = Firebase.verify_id_token(id_token)
            uid = decoded.get("uid") if isinstance(decoded, dict) else None
            if not uid:
                metrics.record_auth_failure("missing_uid")
                log_event(
                    logger,
                    logging.WARNING,
                    "auth_failure",
                    "Decoded token missing uid claim",
                    path=request.path,
                )
                return error_response("Invalid authentication token", 401)
        except Exception as exc:
            metrics.record_auth_failure("invalid_token")
            log_event(
                logger,
                logging.WARNING,
                "auth_failure",
                "Token verification failed",
                path=request.path,
                reason=str(exc),
            )
            return error_response("Invalid or expired authentication token", 401)
        g.user_uid = uid
        return f(uid, *args, **kwargs)
    return decorated


@app.route("/users/create", methods=["POST"])
@rate_limit(limit=5, window_seconds=60)
def create_user():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Invalid JSON payload", 400)
    email, password, validation_err = validate_email_and_password(
        data.get("email"), data.get("password")
    )
    if validation_err:
        return error_response(validation_err, 400)
    try:
        result = Firebase.create_user(email, password)
        log_event(logger, logging.INFO, "user_created", "New user account created", email=email)
        return success_response(result, 200)
    except Exception as e:
        log_event(logger, logging.ERROR, "user_create_error", "Error creating user", error=str(e))
        return error_response("Error creating user", 400)


@app.route("/users/info", methods=["POST"])
@rate_limit(limit=20, window_seconds=60)
@require_auth
def set_user_info(uid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Invalid JSON payload", 400)
    try:
        user_info = {
            "majors": sanitize_string_list(data.get("majors")),
            "minors": sanitize_string_list(data.get("minors")),
            "courses": sanitize_string_list(data.get("courses"), max_items=50),
            "college": sanitize_text(data.get("college"), max_length=100),
            "year": sanitize_text(data.get("year"), max_length=50),
            "about": sanitize_text(data.get("about"), max_length=500),
        }
    except ValueError as val_err:
        return error_response(f"Invalid input: {val_err}", 400)

    try:
        Firebase.set_user_info(uid, user_info)
        return success_response({"message": "User info set successfully", "uid": uid}, 200)
    except Exception as e:
        log_event(logger, logging.ERROR, "user_info_update_error", "Error setting user info", uid=uid, error=str(e))
        return error_response("Error setting user info", 400)


@app.route("/users/info", methods=["GET"])
@rate_limit(limit=30, window_seconds=60)
@require_auth
def get_user_info(uid):
    try:
        user_info = Firebase.get_user_info(uid)
        return success_response(user_info, 200)
    except Exception as e:
        log_event(logger, logging.ERROR, "user_info_fetch_error", "Error getting user info", uid=uid, error=str(e))
        return error_response("Error getting user info", 400)


@app.route("/users/query", methods=["POST"])
@rate_limit(limit=15, window_seconds=60)
@require_auth
def get_user_query(uid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Invalid JSON payload", 400)
    raw_query = data.get("query")
    if not isinstance(raw_query, str) or not raw_query.strip():
        return error_response("Query is required and must be a non-empty string", 400)
    try:
        clean_query = sanitize_text(raw_query, max_length=500)
    except ValueError as val_err:
        return error_response(str(val_err), 400)

    try:
        user_info = Firebase.get_user_info(uid)
        return success_response(QueryManager(clean_query, user_info).response, 200)
    except Exception as e:
        log_event(logger, logging.ERROR, "query_processing_error", "Error generating query response", uid=uid, error=str(e))
        return error_response("Error generating query response", 400)


@app.route('/hash', methods=['POST'])
@rate_limit(limit=30, window_seconds=60)
@require_auth
def generate_message_id(uid):
    try:
        data = request.get_json(silent=True)
        if data is None:
            return error_response("Invalid JSON payload", 400)
        message_id = hashFunction(data)
        return jsonify({'messageID': message_id}), 200
    except Exception as e:
        log_event(logger, logging.ERROR, "hash_error", "Error generating hash", uid=uid, error=str(e))
        return error_response("Internal server error generating message ID", 500)


@app.route("/chats/<chat_id>/messages", methods=["POST"])
@rate_limit(limit=30, window_seconds=60)
@require_auth
def save_chat(uid, chat_id):
    if not validate_safe_identifier(chat_id):
        return error_response("Invalid chat_id format", 400)
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Invalid JSON payload", 400)
        messages = data.get('messages', [])
        if not isinstance(messages, list) or len(messages) > 50:
            return error_response("Messages must be a list of at most 50 items", 400)
        Firebase.save_chat(uid, chat_id, messages)
        return jsonify({'message': 'Messages saved successfully'}), 200
    except Exception as e:
        log_event(logger, logging.ERROR, "chat_save_error", "Error saving messages", uid=uid, error=str(e))
        return error_response("Error saving messages", 400)


@app.route("/chats/<chat_id>", methods=["DELETE"])
@rate_limit(limit=20, window_seconds=60)
@require_auth
def delete_chat(uid, chat_id):
    if not validate_safe_identifier(chat_id):
        return error_response("Invalid chat_id format", 400)
    try:
        Firebase.delete_chat(uid, chat_id)
        return success_response({'message': 'Message deleted successfully'}, 200)
    except Exception as e:
        log_event(logger, logging.ERROR, "chat_delete_error", "Error deleting chat", uid=uid, error=str(e))
        return error_response("Error deleting message", 400)


if __name__ == '__main__':
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug_mode)
