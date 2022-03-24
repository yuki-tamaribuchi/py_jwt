import hmac
from hashlib import sha256

from py_json.src.my_json import loads
from py_base64.src.base64.base64 import base64encode, base64decode

def jwt_decoder(token, secret_key):
	if type(token) == str:
		token = bytes(token, "utf-8")
	if type(secret_key) == str:
		secret_key = bytes(secret_key, "utf-8")

	header, payload, signature = token.split(b".")

	verification_signature = base64encode(bytes(hmac.new(secret_key, header + b"." + payload, sha256).hexdigest(), "utf-8"))
	
	if signature != verification_signature:
		print("Token verification error")
		raise Exception

	decoded_token_dict = {}

	decoded_token_dict["header"] = loads(base64decode(header).decode("utf-8"))
	decoded_token_dict["payload"]= loads(base64decode(payload).decode("utf-8"))

	return decoded_token_dict