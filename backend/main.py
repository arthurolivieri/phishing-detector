from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime
import sqlite3
from urllib.parse import urlparse
import re

app = FastAPI(title="Phishing Detector API", version="1.0.0")

# Configuração de CORS para permitir requisições do frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conexão com o banco de dados
def get_db_connection():
    conn = sqlite3.connect('phishing.db')
    conn.row_factory = sqlite3.Row
    return conn

class URLCheckRequest(BaseModel):
    url: str

class URLCheckResponse(BaseModel):
    url: str
    is_safe: bool
    risk_level: str
    checks: Dict[str, bool]
    details: List[str]
    checked_at: str


@app.get("/")
async def root():
    return {
        "message": "Phishing Detector API",
        "version": "1.0.0",
        "endpoints": {
            "check_url": "/api/check-url",
            "health": "/api/health",
            "stats": "/api/stats"
        }
    }

@app.get("/api/health")
async def health_check():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM phishing_urls")
        count = cursor.fetchone()[0]
        conn.close()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "phishing_urls_in_db": count
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }

def check_in_phishing_database(url: str) -> bool:
    """
    Verifica se a URL está no banco de dados de phishing.
    Retorna bool encontrado
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    url = _normalize_url(url)
    url_lower = url.lower()
    parsed = urlparse(url_lower)
    domain = parsed.netloc
    
    if not domain and parsed.path:
        domain = parsed.path.split('/')[0]
    
    cursor.execute("SELECT target FROM phishing_urls WHERE url = ?", (url_lower,))
    result = cursor.fetchone()
    
    if result:
        conn.close()
        return True
    
    cursor.execute("SELECT target FROM phishing_urls WHERE domain = ? LIMIT 1", (domain,))
    result = cursor.fetchone()
    
    conn.close()
    
    if result:
        return True
    
    return False

@app.post("/api/check-url", response_model=URLCheckResponse)
async def check_url(request: URLCheckRequest):
    """Verifica se uma URL é potencialmente phishing"""
    url = request.url
    
    in_database = check_in_phishing_database(url)
    
    checks = {
        "in_phishing_database": in_database,
        "has_suspicious_numbers": _has_suspicious_numbers(url),
        "has_excessive_subdomains": _has_excessive_subdomains(url),
        "has_special_characters": _has_special_characters(url),
    }
    
    suspicious_count = sum([
        checks["in_phishing_database"],
        checks["has_suspicious_numbers"],
        checks["has_excessive_subdomains"],
        checks["has_special_characters"],
    ])
    
    if checks["in_phishing_database"]:
        risk_level = "malicious"
        is_safe = False
    elif suspicious_count >= 3:
        risk_level = "malicious"
        is_safe = False
    elif suspicious_count >= 1:
        risk_level = "suspicious"
        is_safe = False
    else:
        risk_level = "safe"
        is_safe = True
    
    details = []
    if checks["in_phishing_database"]:
        details.append(f"URL encontrada em base de phishing")
    if checks["has_suspicious_numbers"]:
        details.append("Números substituindo letras detectados")
    if checks["has_excessive_subdomains"]:
        details.append("Uso excessivo de subdomínios")
    if checks["has_special_characters"]:
        details.append("Caracteres especiais suspeitos")
    
    if not details:
        details.append("Nenhuma característica suspeita detectada")
    
    return URLCheckResponse(
        url=url,
        is_safe=is_safe,
        risk_level=risk_level,
        checks=checks,
        details=details,
        checked_at=datetime.now().isoformat()
    )

def _normalize_url(url: str) -> str:
    """
    Normaliza a URL se necessário.
    """
    url = url.strip()

    if not url.startswith(('http://', 'https://', '//')):
        url = 'https://' + url
    
    return url

def _has_suspicious_numbers(url: str) -> bool:
    """
    Detecta possíveis substituições de letras por números (leet) em domínios,
    ex.: g00gle -> google, paypa1 -> paypal, face8ook -> facebook.

    Retorna:
      True  -> suspeito por uso de números no lugar de letras
      False -> não suspeito
    """

    LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
    BRANDS = {
        "google","facebook","instagram","twitter","linkedin","youtube","amazon","microsoft","apple",
        "netflix","paypal","ebay","whatsapp","spotify","reddit","github","stackoverflow","wikipedia",
        "wordpress","yahoo","zoom","dropbox","adobe","discord"
    }
    PHISH_WORDS = {"login","account","verify","update","confirm","signin","password","support"}
    TOKENS = BRANDS | PHISH_WORDS

    COMPOSITE_TLDS = {
        "com.br","org.br","net.br","gov.br","edu.br","mil.br",
        "co.uk","ac.uk","gov.uk","org.uk",
        "com.au","co.jp","co.kr","co.za",
        "co.nz","net.nz","org.nz",
        "com.mx","org.mx","net.mx",
        "com.ar","gov.ar","org.ar",
    }

    def _extract_host(u: str) -> str:
        parsed = urlparse(u)
        host = (parsed.netloc or parsed.path.split("/")[0]).lower()
        if not host:
            return ""
        host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        return host

    def _registrable_part(host: str) -> str:
        parts = host.split(".")
        if len(parts) <= 1:
            return host
        last2 = ".".join(parts[-2:])
        if last2 in COMPOSITE_TLDS and len(parts) >= 3:
            # exemplo: secure.login.paypal.com.br -> remove ".com.br"
            return ".".join(parts[:-2])
        # caso comum: remove apenas o último rótulo (ex.: ".com")
        return ".".join(parts[:-1])

    # --- pipeline -------------------------------------------------------------
    url = _normalize_url(url)
    host = _extract_host(url)
    if not host:
        return False

    domain_to_check = _registrable_part(host)

    # Se for IP ou só números/pontos, não é leet numérico
    if all(c.isdigit() or c == "." for c in host):
        return False

    # Devem haver letras e números misturados no rótulo analisado
    has_digit = any(c.isdigit() for c in domain_to_check)
    has_alpha = any(c.isalpha() for c in domain_to_check)
    if not (has_digit and has_alpha):
        return False

    # Troca números por letras e procura tokens como segmentos
    deleet = domain_to_check.translate(LEET_MAP)
    segmented = re.sub(r"[^a-z0-9]+", " ", deleet)

    for t in TOKENS:
        if re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", segmented):
            return True

    if re.search(r"[a-z]0{2,}[a-z]", domain_to_check):
        return True

    if len(re.findall(r"[a-z]\d[a-z]", domain_to_check)) >= 2:
        return True

    return False

def _has_excessive_subdomains(url: str) -> bool:
    """
    Detecta uso excessivo de subdomínios, uma técnica comum em phishing.
    """

    url = _normalize_url(url)
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    if not domain and parsed.path:
        domain = parsed.path.split('/')[0].lower()
    
    if not domain:
        return False
    
    domain = domain.split(':')[0]
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    parts = domain.split('.')
    
    if len(parts) < 2:
        return False
    
    composite_tlds = [
        'co.uk', 'com.br', 'com.au', 'co.jp', 'co.kr', 'co.za',
        'gov.br', 'org.br', 'net.br', 'edu.br', 'mil.br',
        'ac.uk', 'gov.uk', 'org.uk',
        'co.nz', 'net.nz', 'org.nz',
        'com.mx', 'org.mx', 'net.mx',
        'com.ar', 'gov.ar', 'org.ar'
    ]
    
    tld_parts = 1
    
    if len(parts) >= 2:
        potential_tld = f"{parts[-2]}.{parts[-1]}"
        if potential_tld in composite_tlds:
            tld_parts = 2
    
    # Calcular número de subdomínios
    subdomain_count = len(parts) - 1 - tld_parts
    
    is_suspicious = subdomain_count > 3
    
    return is_suspicious

def _has_special_characters(url: str) -> bool:
    """
    Detecta caracteres especiais suspeitos em URLs de phishing.
    """
    url = _normalize_url(url)
    
    parsed = urlparse(url)
    domain = parsed.netloc
    
    if not domain and parsed.path:
        domain = parsed.path.split('/')[0]
    
    if not domain:
        return False
    
    domain = domain.split(':')[0].lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    
    domain_parts = domain.split('.')
    if len(domain_parts) > 1:
        domain_to_check = '.'.join(domain_parts[:-1])
    else:
        domain_to_check = domain
    
    if '@' in domain:
        return True
    
    if '--' in domain_to_check or '__' in domain_to_check:
        return True
    
    hyphen_count = domain_to_check.count('-')
    underscore_count = domain_to_check.count('_')
    
    if underscore_count >= 2:
        return True
    
    if hyphen_count > 3:
        return True
    
    if hyphen_count >= 2 and underscore_count >= 1:
        return True
    
    suspicious_patterns = [
        r'-{3,}',           # 3+ hífens consecutivos
        r'_{2,}',           # 2+ underscores consecutivos
        r'[_-][0-9]+[_-]',  # números entre hífens/underscores
        r'(login|secure|verify|account|update)-+\w+-+(com|net|org)',  # padrões de phishing
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, domain_to_check):
            return True
    
    return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
