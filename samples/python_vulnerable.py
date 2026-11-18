import os
import pickle

api_key = "sk_live_1234567890abcdef"

def execute_user_task(query_param):
    query = "SELECT * FROM users WHERE username = " + query_param
    os.system("echo " + query_param)
    eval("10 + 20")
    obj = pickle.loads(b"data")
