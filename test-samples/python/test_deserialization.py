"""Test: Deserialization vulnerabilities"""
import pickle
import marshal
import shelve
import yaml

from flask import Flask, request

app = Flask(__name__)

@app.route("/load")
def load_data():
    data = request.data
    
    # Insecure pickle deserialization
    obj = pickle.loads(data)
    
    # pickle.load from file
    with open("data.pkl", "rb") as f:
        obj2 = pickle.load(f)
    
    # marshal.loads
    obj3 = marshal.loads(data)
    
    # shelve
    db = shelve.open("mydata")
    
    # yaml.load without SafeLoader
    config = yaml.load(data)
    
    # yaml.unsafe_load
    config2 = yaml.unsafe_load(data)
    
    return str(obj)
