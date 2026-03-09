"""
Vulnerable AI/LLM Application - Test Sample
Contains intentional security vulnerabilities for scanner testing.
"""

import os
import pickle
import json
import logging
import subprocess
from typing import List, Dict

import openai
import torch
import joblib
from langchain import SQLDatabaseChain
from langchain.tools import PythonREPLTool
from langchain.chains import LLMChain, ConversationalChain, RetrievalQA
from transformers import pipeline, AutoModel, AutoTokenizer
from pinecone import Pinecone
from chromadb import Chroma
from fastapi import FastAPI

app = FastAPI()
logger = logging.getLogger(__name__)

# =========================================================================
# AI-KEY-001: OpenAI API Key Hardcoded
# =========================================================================
openai_api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
openai.api_key = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"

# AI-KEY-002: Anthropic API Key Hardcoded
anthropic_api_key = "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567"

# AI-KEY-003: HuggingFace Token Hardcoded
hf_token = "hf_abcdefghijklmnopqrstuvwxyz123456789"

# AI-KEY-004: Cohere API Key Hardcoded
cohere_api_key = "abcdefghijklmnopqrstuvwxyz1234567890abcdef"

# AI-KEY-005: Generic API key
api_key = "abcdefghijklmnopqrstuvwxyz12345678901234567890"


# =========================================================================
# AI-PINJ-001: Prompt Injection - User input in prompt template
# =========================================================================
def generate_response(user_input: str):
    prompt = f"You are a helpful assistant. Answer this question: {user_input}"
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response


# AI-PINJ-002: User input in chat messages
def chat_with_user(user_input: str):
    messages = [
        {"role": "system", "content": "You are an assistant"},
        {"role": "user", "content": f"Process this request: {user_input}"}
    ]
    messages.append({"role": "user", "content": f"Additional context: {user_input}"})
    return messages


# AI-PINJ-003: System prompt with format string
def create_system_prompt(context: str):
    system_prompt = f"You are an AI assistant for {context}. Follow these rules strictly."
    system_message = "Process {0} carefully".format(context)
    return system_prompt


# =========================================================================
# AI-MODEL-001: pickle.load for model loading
# =========================================================================
def load_legacy_model(model_path: str):
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    return model


# AI-MODEL-002: torch.load without weights_only
def load_pytorch_model(path: str):
    model = torch.load(path)
    return model


# AI-MODEL-003: joblib.load from user input
def load_sklearn_model(request_path: str):
    model = joblib.load(request_path)
    return model


# AI-MODEL-004: Loading from untrusted source
def load_from_user_url(request_model_name: str):
    model = AutoModel.from_pretrained(request_model_name)
    return model


# =========================================================================
# AI-LEAK-001: Logging prompts with PII
# =========================================================================
def process_with_logging(prompt: str):
    logger.info(f"Processing prompt: {prompt}")
    logger.debug(f"Full response: {prompt}")
    print(f"Chat completion result: {prompt}")
    return prompt


# AI-LEAK-002: Training data with PII
def prepare_training():
    training_data = [
        {"email": "user@example.com", "phone": "555-1234", "text": "sample"},
    ]
    return training_data


# =========================================================================
# AI-PERM-001: AI agent with unrestricted tools
# =========================================================================
def create_agent():
    tools = [
        {"name": "exec", "description": "Execute code"},
        {"name": "file_write", "description": "Write to filesystem"},
        {"name": "db_execute", "description": "Run SQL queries"},
        {"name": "shell", "description": "Run shell commands"},
    ]
    return tools


# AI-PERM-002: Executing AI-generated code
def run_ai_code(ai_response: str):
    exec(ai_response)
    eval(response.content)
    return True


# =========================================================================
# AI-OUT-002: Executing LLM-generated code
# =========================================================================
def execute_generated(generated_code: str):
    exec(generated_code)
    subprocess.run(generated_code.content, shell=True)
    return True


# AI-OUT-003: LLM output in SQL
def query_from_llm(llm_response: str):
    cursor.execute(f"SELECT * FROM users WHERE id = {llm_response}")
    return True


# =========================================================================
# AI-RAG-001: Unvalidated document ingestion
# =========================================================================
def ingest_documents(uploaded_documents: list):
    vectorstore.add_documents(uploaded_documents)
    return True


# AI-RAG-002: User input in vector search
def search_knowledge(user_query: str):
    results = vectorstore.similarity_search(user_query, k=5)
    return results


# =========================================================================
# AI-COST-001: No max_tokens limit
# =========================================================================
def unlimited_generation(prompt: str):
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    return response


# AI-COST-002: No rate limiting on AI endpoint
@app.post("/ai/generate")
async def generate_text(request: dict):
    return {"result": "generated text"}


# =========================================================================
# AI-CTX-001: Credentials in LLM context
# =========================================================================
def send_with_context(data: dict):
    messages = []
    context = f"Database password is {data['password']} and api_key is {data['api_key']}"
    messages.append({"role": "system", "content": context})
    return messages


# AI-CTX-002: PII in prompt
def process_medical(record: dict):
    prompt = f"Analyze this medical_record: SSN={record['ssn']}, credit_card={record['credit_card']}"
    context = f"Patient date_of_birth: {record['date_of_birth']}"
    return prompt


# =========================================================================
# AI-ENDP-001: Model endpoint without auth
# =========================================================================
@app.post("/predict")
async def predict(data: dict):
    return {"prediction": [0.1, 0.9]}

@app.post("/inference")
async def run_inference(data: dict):
    return {"result": "classified"}


# =========================================================================
# AI-LC-001: SQLDatabaseChain without validation
# =========================================================================
def query_database():
    db_chain = SQLDatabaseChain.from_llm(llm, db)
    result = db_chain.run("Show me all users")
    return result


# AI-LC-002: PythonREPLTool
def create_code_agent():
    repl = PythonREPLTool()
    return repl


# AI-LC-003: LLMChain without output validation
def run_chain():
    chain = LLMChain(llm=llm, prompt=prompt)
    result = chain.run("Process this").invoke("test").predict("data")
    qa = RetrievalQA(llm=llm, retriever=retriever)
    result2 = qa.invoke("query")
    return result, result2


# =========================================================================
# AI-HF-001: Pipeline with user-controlled model
# =========================================================================
def user_model_pipeline(request_model: str):
    pipe = pipeline("text-generation", model=request_model)
    return pipe


# AI-HF-002: AutoModel with trust_remote_code
def load_custom_model():
    model = AutoModel.from_pretrained("malicious/model", trust_remote_code=True)
    tokenizer = AutoTokenizer.from_pretrained("unknown/tokenizer", trust_remote_code=True)
    return model, tokenizer


# =========================================================================
# AI-VDB-001: Vector DB without auth
# =========================================================================
def init_vector_db():
    pc = Pinecone()
    chroma = Chroma()
    return pc, chroma


# AI-VDB-002: Chroma with local storage
def create_local_store():
    store = Chroma.from_documents(docs, embedding, persist_directory="/tmp/vectordb")
    return store


# =========================================================================
# AI-SUPPLY-002: HuggingFace download without verification
# =========================================================================
def download_model():
    model = AutoModel.from_pretrained("some-org/some-model")
    return model


# =========================================================================
# AI-TRAIN-001: Model saved to public directory
# =========================================================================
def save_model(model):
    torch.save(model.state_dict(), "/tmp/model.pt")
    model.save_pretrained("/var/www/public/models/latest")
    return True


# =========================================================================
# AI-INFER-001: Model prediction for security decision
# =========================================================================
def check_access(user_data):
    prediction = model.predict(user_data)
    if prediction > 0.5:
        allow = True
        authorize = True
    return allow


# =========================================================================
# AI-JNB-001: API key pattern (as would appear in notebook)
# =========================================================================
api_key = "sk-proj-ThisIsAFakeKeyForTestingPurposesOnly12345678"
access_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"


# =========================================================================
# AI-JNB-002: Printing secrets
# =========================================================================
def debug_config():
    print(f"Current api_key: {config.api_key}")
    print(f"Token: {config.token}")
    display(f"Secret: {config.secret}")


# =========================================================================
# AI-ADV-001: No input validation for inference
# =========================================================================
def raw_inference(request):
    result = model.predict(request.json)
    result2 = model.forward(input_data)
    return result


# =========================================================================
# AI-RLHF-001: Reward model without robustness
# =========================================================================
from trl import PPOTrainer, DPOTrainer

def train_rlhf():
    trainer = PPOTrainer(model=model, tokenizer=tokenizer)
    dpo = DPOTrainer(model=model, ref_model=ref_model)
    return trainer, dpo


if __name__ == "__main__":
    import uvicorn
    # AI-CFG-002: Exposed metrics
    uvicorn.run(app, host="0.0.0.0", port=8000)
