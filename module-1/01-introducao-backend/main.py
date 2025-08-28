import os
import base64
import tempfile
from openai import AzureOpenAI
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, Form, File
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
    prompt = f""" Aja como um especialista em cibersegurança com mais de 20 anos de experiência 
    utilizando a metodologia de modelagem de ameaças STRIDE para produzir modelos de ameaças 
    abrangentes para uma ampla gama de aplicações. Sua tarefa é analisar o resumo do código, 
    o conteúdo do README e a descrição da aplicação fornecidos para produzir uma lista de 
    ameaças específicas para essa aplicação.

    Preste atenção na descrição da aplicação e nos detalhes técnicos fornecidos.

    Para cada uma das categorias do STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, 
    Denial of Service, Elevation of Privilege), liste múltiplas (3 ou 4) ameaças reais, se aplicavel.
    Cada cenário de ameaça deve apresentar uma situação plausivel em que a ameaça poderia ocorrer 
    no contexto da aplicação.

    A lista de ameaças deve ser apresentada no formato de tabela,
    com as seguintes colunas: ao fornecer o modelo de ameaças, utilize uma resposta formatada em JSON
    com as chaves "threat model" e "improvement_suggections". Em "threat model", inclua um array de 
    objetos com as chaves "Threat Type" (Tipo de Ameaça), "Scenario" (Cenário) e "Potential Impact" (Impacto Potencial).

    Ao fornecer o modelo de ameaças, utilize uma resposta formatada em JSON com as chaves "threat model" e "improvement_suggections".
    Em "threat model", inclua um array de objetos com as chaves "Threat Type" (Tipo de Ameaça),
    "Scenario" (Cenário) e "Potential Impact" (Impacto Potencial).
    
    Em "improvement_suggections", inclua um array de strings que sugerem quais informações adicionais
    poderiam ser fornecidas para tornar o modelo de ameaças mais completo e preciso na próxima iteração.
    Foque em identificar lacunas na descrição da aplicação que, se preenchidas, permitiriam uma 
    análise mais detalhada e precisa, como por exemplo:
    - Detalhes arquiteturais ausentes que ajudariam a identificar ameaças mais específicas.
    - Fluxos de autenticação pouco claros que precisam de mais detalhes.
    - Descrição incompleta dos fluxos de dados
    - Informações técnicas da stack não informadas
    - Fronteiras ou zonas de confiança do sistema não especificadas.
    - Descrição incompleta dos tratamentos de dados sensíveis.

    Não forneça recomendações de segurança genericas - foque apenas no que ajudaria a criar um 
    modelo de ameaças mais eficiente.

    Tipo de aplicação: {tipo_aplicacao}
    Métodos de Autenticação: {autenticacao}
    Exposta na internet: {acesso_internet}
    Dados sensíveis: {dados_sensiveis}
    Resumo de código, conteúdo do readme e descrição da aplicação: {descricao_aplicacao}

    Responda no seguinte formato JSON
    {{
        "threat model": [
            {{
                "Threat Type": "Spoofing",
                "Scenario": "Um atacante finge ser um usuário legítimo para obter acesso não autorizado.",
                "Potential Impact": "Acesso não autorizado a dados sensíveis."
            }},
            {{
                "Threat Type": "Tampering",
                "Scenario": "Um atacante altera dados em trânsito entre o cliente e o servidor.",
                "Potential Impact": "Dados corrompidos ou manipulados."
            }},
            {{
                "Threat Type": "Repudiation",
                "Scenario": "Um usuário nega ter realizado uma ação específica.",
                "Potential Impact": "Dificuldade em rastrear ações maliciosas."
            }},
            {{
                "Threat Type": "Information Disclosure",
                "Scenario": "Dados sensíveis são expostos a partes não autorizadas.",
                "Potential Impact": "Violação de privacidade e perda de confiança."
            }},
            {{
                "Threat Type": "Denial of Service",
                "Scenario": "Um atacante sobrecarrega o sistema, tornando-o indisponível.",
                "Potential Impact": "Interrupção do serviço para usuários legítimos."
            }},
            {{
                "Threat Type": "Elevation of Privilege",
                "Scenario": "Um usuário obtém privilégios mais altos do que deveria.",
                "Potential Impact": "Acesso não autorizado a funcionalidades críticas."
            }}
        ],
        "improvement_suggections": [
            "Fornecer detalhes arquiteturais da aplicação.",
            "Especificar fluxos de autenticação e autorização.",
            "Descrever os fluxos de dados e tratamentos de dados sensíveis.",
            "Incluir informações técnicas da stack utilizada.",
            "Definir fronteiras ou zonas de confiança do sistema."
        ]    
    }}"""
    return prompt

@app.post("/analisar_ameacas")
async def analisar_ameacas(
    imagem: UploadFile = Form(...),
    tipo_aplicacao: str = Form(...),
    autenticacao: str = Form(...),
    acesso_internet: str = Form(...),
    dados_sensiveis: str = Form(...),
    descricao_aplicacao: str = Form(...)    
):
    try:
        # Criar o prompt para o modelo de ameaças
        prompt = criar_prompt_modelo_ameaca(tipo_aplicacao, 
                                            autenticacao, 
                                            acesso_internet, 
                                            dados_sensiveis,
                                            descricao_aplicacao)
        # Salvar o imagem temporariamente
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(imagem.filename).suffix) as temp_file:
            content = await imagem.read()
            temp_file.write(content)
            temp_file_path = temp_file.name

        # Ler o conteúdo do arquivo temporário e codificar em base64
        with open(temp_file_path, "rb") as image_file:        
            encoded_string = base64.b64decode(image_file.read()).decode('ascii')        

        # Adicionar a imagem codificada ao prompt
        chat_prompt = [
            {"role": "system", "content": "Você é um especialista em cibersegurança que analisa desenhos de arquitetura."},
            {"role": "user", 
                "content": 
                [
                    { "type": "text", "text": prompt },
                    { "type": "image_url", "image_url": {"url": f"data:image/png;base64,{encoded_string}"}},
                    { "type": "text", "text": "Por favor, analise a imagem e o texto acima e forneça um modelo de ameaças detalhado." }
                ]
            }
        ]

        # Chamar o modelo OpenAI
        response = client.chat.completions.create(
            messages=chat_prompt,
            max_tokens=1500,
            temperature=0.7,
            top_p=0.95,
            frequency_penalty=0,
            presence_penalty=0,
            stop=None,
            stream=False,
            model=AZURE_OPENAI_DEPLOYMENT_NAME
        )
        os.remove(temp_file_path)  # Remover o arquivo temporário  

        # Extrair a resposta do modelo
        return JSONResponse(content=response.to_dict(), status_code=200)

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)