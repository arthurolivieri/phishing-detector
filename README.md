# Phishing Detector

Ferramenta para detecção de URLs de phishing desenvolvida para a disciplina de Tecnologias Hacker (Insper).

## 📋 Sobre o Projeto

Sistema de detecção de phishing que implementa os requisitos do **Conceito C**, realizando verificações básicas de URLs suspeitas através de uma interface web simples e intuitiva.

Vídeo de demonstração: https://youtu.be/m_IG7jse4YY

## ✨ Funcionalidades

### Verificações Implementadas

1. **Base de Dados de Phishing**
   - Verificação contra base com ~50.000 URLs maliciosas conhecidas
   - Dados provenientes do PhishTank (verified_online.csv)
   - Busca por URL completa e domínio

2. **Números Substituindo Letras**
   - Detecta substituições comuns: 0→O, 1→I/L, 3→E, 4→A, 5→S
   - Exemplos: `g00gle.com`, `paypa1.com`, `fac3book.com`
   - Whitelist de domínios legítimos (Google, Facebook, Amazon, etc.)

3. **Subdomínios Excessivos**
   - Identifica uso suspeito de múltiplos subdomínios
   - Exemplo: `login.secure.verify.paypal.com.malicious.com`
   - Suporta TLDs compostos (.com.br, .co.uk)

4. **Caracteres Especiais Suspeitos**
   - Detecta @ no domínio (técnica de ofuscação)
   - Hífens consecutivos (`paypal--login.com`)
   - Excesso de underscores e hífens

### Interface Web

- Formulário simples para inserção de URLs
- Tabela com histórico de verificações
- Indicadores visuais por nível de risco:
  - 🟢 **Verde**: URL segura
  - 🟡 **Amarelo**: URL suspeita
  - 🔴 **Vermelho**: URL maliciosa
- Detalhamento das características detectadas

## 🚀 Como Rodar

### Pré-requisitos

- Docker
- Docker Compose

### Execução com Docker Compose

1. Clone o repositório:
```bash
git clone <url-do-repositorio>
cd phishing-detector
```

2. Inicie os containers:
```bash
docker compose up --build
```

3. Acesse a aplicação:
   - **Frontend**: http://localhost:5173
   - **Backend API**: http://localhost:8000
   - **API Docs**: http://localhost:8000/docs

> **Nota**: A base de dados `phishing.db` já está incluída no repositório com ~50.000 URLs de phishing carregadas.

## 📡 API Endpoints

- `GET /` - Informações da API
- `GET /api/health` - Health check e estatísticas do banco
- `POST /api/check-url` - Verificar uma URL

## 🧪 Exemplos de Teste

URLs maliciosas para testar:
- `paypa1-secure.com`
- `login.verify.secure.paypal.com.evil.com`
- `g00gle-login.com`
- `amazon--verify.com`
- `face8ook.com`

URLs legítimas para testar:
- `https://www.google.com`
- `https://secure.facebook.com`
- `https://www.paypal.com`

## 📊 Níveis de Risco

O sistema classifica URLs em 3 níveis:

- **Safe (Segura)**: Nenhuma característica suspeita detectada
- **Suspicious (Suspeita)**: 1-2 características suspeitas encontradas
- **Malicious (Maliciosa)**: 3+ características suspeitas OU encontrada na base de phishing

## 🎯 Conceito C - Requisitos Atendidos

✅ Verificação contra listas de phishing conhecidas (PhishTank)  
✅ Identificação de números substituindo letras  
✅ Detecção de subdomínios excessivos  
✅ Identificação de caracteres especiais suspeitos  
✅ Página web com interface para inserção de URLs  
✅ Exibição de resultados em formato de tabela  
✅ Indicadores visuais (verde/amarelo/vermelho)  

## 📝 Estrutura do Projeto

```
phishing-detector/
├── backend/
│   ├── main.py              # API FastAPI
│   ├── load_phishing_db.py  # Script de carga do banco
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   └── App.jsx          # Componente React principal
│   ├── Dockerfile
│   └── package.json
├── compose.yaml             # Orquestração Docker
└── README.md
```
