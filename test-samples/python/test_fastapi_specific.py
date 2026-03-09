"""Test: FastAPI-specific vulnerabilities"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# CORS allow all origins
allow_origins = ["*"]
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])

@app.post("/data")
async def create_data(request: Request):
    # No authentication on state-changing endpoint
    data = await request.json()
    return {"status": "created"}

@app.delete("/items/{item_id}")
async def delete_item(item_id: str):
    # No auth dependency
    return {"deleted": item_id}
