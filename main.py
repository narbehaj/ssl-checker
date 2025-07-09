# main.py 改造示例
from fastapi import FastAPI
import subprocess

app = FastAPI()

@app.get("/check")
def check_ssl(domain: str):
    result = subprocess.run(["python", "ssl_checker.py", domain], capture_output=True, text=True)
    return {"output": result.stdout}
