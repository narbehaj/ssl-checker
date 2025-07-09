from fastapi import FastAPI
import subprocess
import os

app = FastAPI()

@app.get("/check")
def check_ssl(domain: str):
    try:
        # 获取当前文件绝对路径的目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(current_dir, "ssl_checker.py")
        
        # 调用脚本（确保 python 在 PATH 中）
        result = subprocess.run(
            ["python", script_path, domain],
            capture_output=True,
            text=True
        )
        
        # 返回 stdout 或 stderr
        output = result.stdout if result.stdout else result.stderr
        return {"output": output}
    except Exception as e:
        return {"error": str(e)}
