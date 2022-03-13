import hmac
from hashlib import sha256
from json import loads

from base64 import b64decode, b64encode

def jwt_decoder(token, secret_key):
	if type(token) == str:
		token = bytes(token, "utf-8")
	if type(secret_key) == str:
		secret_key = bytes(secret_key, "utf-8")

	header, payload, signature = token.split(b".")

	verification_signature = b64encode(bytes(hmac.new(secret_key, header + b"." + payload, sha256).hexdigest(), "utf-8"))
	
	if signature != verification_signature:
		print("Token verification error")
		raise Exception

	decoded_token_dict = {}

	decoded_token_dict["header"] = loads(b64decode(header))
	decoded_token_dict["payload"]= loads(b64decode(payload))

	return decoded_token_dict