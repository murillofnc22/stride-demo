import os
import base64
import tempfile
from openai import AzureOpenAI
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import JSONResponse
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware

env_path = Path(__file__).resolve(strict=True).parent / '.env'
load_dotenv(dotenv_path=env_path)

AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION")
AZURE_OPENAI_DEPLOYMENT_NAME = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = AzureOpenAI(
    api_key=AZURE_OPENAI_API_KEY,
    azure_enpoint=AZURE_OPENAI_ENDPOINT,
    api_version=AZURE_OPENAI_API_VERSION,
    azure_deployment=AZURE_OPENAI_DEPLOYMENT_NAME)

def criar_prompt_modelo_ameaca(tipo_aplicacao, autenticacao, acesso_internet, dados_sensiveis, descricao_aplicacao):
    prompt = f"""
    Voc ê é um especialista em segurança da informação. 
    Sua tarefa é criar um modelo de ameaças para uma aplicação com as seguintes características:

    Tipo de aplicação: {tipo_aplicacao}
    Autenticação: {autenticacao}
    Acesso à internet: {acesso_internet}
    Dados sensíveis: {dados_sensiveis}

    Considere os seguintes aspectos ao criar o modelo de ameaças:
    1. Identifique possíveis ameaças e vulnerabilidades.
    2. Avalie o impacto e a probabilidade de cada ameaça.
    3. Proponha medidas de mitigação para cada ameaça identificada.

    Forneça o modelo de ameaças em formato estruturado, como uma lista ou tabela.
    """
    return prompt