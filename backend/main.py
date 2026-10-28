import hashlib as h
import json
import os
import secrets as st
import string as s
from openai import OpenAI

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_secure_rng = st.SystemRandom()


def shuffle(p: str) -> str:
    char_list = list(p)
    _secure_rng.shuffle(char_list)
    return "".join(char_list)


def hashFunction(data) -> str:
    salt_len = st.randbelow(5) + 5
    alphabet = s.ascii_letters + s.digits
    salt = "".join(st.choice(alphabet) for _ in range(salt_len))
    x = h.sha256((str(data) + salt).encode("utf-8")).hexdigest()
    w = str(st.randbelow(16))
    b = st.token_hex(16)
    return shuffle(f"{w}{x}+{b}")


def _load_openai_api_key() -> str:
    env_key = os.getenv("OPENAI_API_KEY")
    if env_key:
        return env_key
    config_path = os.getenv("CONFIG_JSON_PATH", os.path.join(BASE_DIR, "config.json"))
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as cfg_file:
            config = json.load(cfg_file)
            return config.get("openai_api_key", "")
    return ""


def _load_question_types() -> dict:
    qt_path = os.path.join(BASE_DIR, "query_types.json")
    if os.path.exists(qt_path):
        with open(qt_path, "r", encoding="utf-8") as qt_file:
            return json.load(qt_file)
    return {}


question_types = _load_question_types()


def make_prompt(query: str) -> str:
    return (
        """
    Respond to this prompt with a JSON object ONLY! No other output.

    Consider the following query types with parameters:"""
        + str(question_types)
        + """
    The keys in the parameter list represent the parameters, and the values of those keys
    represent the data types that those parameters are.

    Given the following query:"""
        + query
        + """, identify which query type it is and what
        the relevant parameters are.

        Print the output as a JSON object of the following form:

        {
            "query_type": ....,
            "parameters": ....
        }

        If the query is empty or doesn't make sense, say that it is an unsupported query_type
    """
    )


def get_query_details(query: str) -> dict:
    api_key = _load_openai_api_key()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a strict JSON classifier for university course queries."},
            {"role": "user", "content": make_prompt(query)},
        ],
        response_format={"type": "json_object"},
        max_tokens=200,
    )
    return json.loads(response.choices[0].message.content)
