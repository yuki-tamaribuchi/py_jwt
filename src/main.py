from jwt.jwt import JWT
from jwt.decoder import jwt_decoder
import time

if __name__ == "__main__":
	
	jwt = JWT(payload={"message":"hello,world!", "iat":time.time(), "exp":time.time()+600})

	token = jwt.get_token()
	print("token: ", token)

	decoded_token_dict = jwt_decoder(token, "secret")
	print("decoded_token_dict: ", decoded_token_dict)