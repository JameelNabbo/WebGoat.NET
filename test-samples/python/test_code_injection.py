"""Test: Code Injection vulnerabilities"""
from flask import Flask, request

app = Flask(__name__)

@app.route("/calc")
def calculate():
    expr = request.args.get("expression")
    
    # eval with user input
    result = eval(expr)
    
    # exec with user input
    exec(expr)
    
    # eval with f-string
    eval(f"print({expr})")
    
    # compile with user input
    code = compile(expr, "<string>", "exec")
    
    return str(result)

def dynamic_eval():
    # eval with dynamic string concatenation
    operation = "some" + "thing"
    result = eval("2 + " + operation)
    return result
