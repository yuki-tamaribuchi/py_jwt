import hmac
from hashlib import sha256
from json import dumps

from base64 import b64encode

class JWT:
	def __init__(self, payload, alg="HS256", secret_key="secret"):
		self.__typ = "JWT"
		self.__alg = alg
		self.__secret_key = bytes(secret_key, "utf-8")
		self.__payload = bytes(dumps(payload), "utf-8")

		self.__gen_header()
		self.__gen_signature()
		self.__gen_token()


	def __gen_header(self):
		header_dict = {
			"alg": self.__alg,
			"typ": self.__typ
		}
		self.__header = bytes(dumps(header_dict), "utf-8")

	def __gen_signature(self):
		b64_header = b64encode(self.__header)
		b64_payload = b64encode(self.__payload)
		message = b64_header + b"." + b64_payload
		if self.__alg == "HS256":
			self.__signature = bytes(hmac.new(self.__secret_key, message, sha256).hexdigest(), "utf-8")
		else:
			print("Implemented only HS256")

	
	def __gen_token(self):
		self.__token = b64encode(self.__header) + b"." + b64encode(self.__payload)+ b"." + b64encode(self.__signature)
	

	def get_token(self):
		return self.__token