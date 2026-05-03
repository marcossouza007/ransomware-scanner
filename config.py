# ============================================================================
# CONFIGURAÇÕES GLOBAIS - RANSOMWARE SCANNER v2.0
# ============================================================================

import os
from enum import Enum
from pathlib import Path

# ============================================================================
# DIRETÓRIOS
# ============================================================================

BASE_DIR = Path(__file__).parent.resolve()
QUARANTINE_DIR = BASE_DIR / 'quarantine'
LOGS_DIR = BASE_DIR / 'logs'
REPORTS_DIR = BASE_DIR / 'reports'
CHARTS_DIR = REPORTS_DIR / 'charts'

# Criar diretórios se não existirem
for directory in [QUARANTINE_DIR, LOGS_DIR, REPORTS_DIR, CHARTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# ============================================================================
# CONFIGURAÇÕES DE SCAN
# ============================================================================

SCAN_CONFIG = {
    'threat_threshold': 0.5,      # Score mínimo para detectar ameaça (0-1)
    'block_size': 4096,            # Tamanho do bloco para análise de entropia
    'recursive': True,             # Scan recursivo de diretórios
    'max_file_size': 100 * 1024 * 1024,  # 100 MB - limite de tamanho
}

# ============================================================================
# EXTENSÕES SUSPEITAS
# ============================================================================

SUSPICIOUS_EXTENSIONS = [
    # Ransomware comum
    '.locked', '.enc', '.encrypted', '.crypto', '.crypt',
    '.vault', '.pay', '.ransom', '.xtbl', '.onion', '.4444',
    '.dfndr', '.clop', '.blackcat', '.lockbit',
    # Variantes conhecidas
    '.dharma', '.jigsaw', '.petya', '.wannacry', '.cerber',
    '.cryptowall', '.cryptolocker', '.shade', '.teslacrypt',
    # Genérico
    '.recovered', '.malware', '.virus'
]

# ============================================================================
# BANCO DE PALAVRAS-CHAVE DE AMEAÇA
# ============================================================================

THREAT_DATABASE = {
    'ransomware': [
        'encrypt', 'lock', 'crypto', 'payment', 'bitcoin',
        'ransom', 'wallet', 'pay', 'decrypt', 'key',
        'restore', 'recover', 'contact', 'email', 'telegram'
    ],
    'dropper': [
        'download', 'execute', 'inject', 'spawn', 'shellcode',
        'loader', 'payload', 'stage', 'beacon', 'connect'
    ],
    'wiper': [
        'delete', 'format', 'remove', 'erase', 'overwrite',
        'wipe', 'destroy', 'unrecoverable', 'permanent'
    ],
    'exfiltration': [
        'send', 'upload', 'post', 'transmit', 'exfil',
        'steal', 'leak', 'data', 'credential', 'password'
    ],
    'c2_communication': [
        'http://', 'https://', 'socket', 'connect', 'beacon',
        'server', 'command', 'control', 'dns', 'request'
    ]
}

# ============================================================================
# CHAVES DE DESCRIPTOGRAFIA CONHECIDAS
# ============================================================================

KNOWN_RANSOMWARE_KEYS = {
    'wannacry': b'THIS_IS_RANSOMWARE_KEY_WANNACRY_XOR',
    'petya': b'THIS_IS_RANSOMWARE_KEY_PETYA_MASTER_',
    'lockit': b'THIS_IS_RANSOMWARE_KEY_LOCKIT_CRYPT',
    'cerber': b'THIS_IS_RANSOMWARE_KEY_CERBER_VAULT_',
    'shade': b'THIS_IS_RANSOMWARE_KEY_SHADE_ENCRY__',
    'generic': b'GENERIC_RANSOMWARE_KEY_PLACEHOLDER_1',
}

# ============================================================================
# MÉTODOS DE SOBRESCRITA SEGURA
# ============================================================================

class SecureOverwriteMethod(Enum):
    """Métodos de sobrescrita segura para deletar arquivos"""
    SIMPLE_ZEROS = 'simple_zeros'       # 1 pass com zeros
    RANDOM = 'random'                   # 1 pass com aleatório
    DOD_5220_22 = 'dod_5220_22'         # 3 passes (RECOMENDADO)
    SCHNEIER = 'schneier'               # 7 passes
    GUTMANN = 'gutmann'                 # 35 passes (MÁXIMO)
    DBAN = 'dban'                       # 4 passes
    NIST = 'nist'                       # 3 passes
    CUSTOM = 'custom'                   # Customizado

# Configuração padrão de sobrescrita
DEFAULT_OVERWRITE_METHOD = SecureOverwriteMethod.DOD_5220_22
OVERWRITE_PASSES = {
    SecureOverwriteMethod.SIMPLE_ZEROS: 1,
    SecureOverwriteMethod.RANDOM: 1,
    SecureOverwriteMethod.DOD_5220_22: 3,
    SecureOverwriteMethod.SCHNEIER: 7,
    SecureOverwriteMethod.GUTMANN: 35,
    SecureOverwriteMethod.DBAN: 4,
    SecureOverwriteMethod.NIST: 3,
}

# ============================================================================
# CLASSIFICAÇÃO DE RISCO
# ============================================================================

RISK_LEVELS = {
    'critical': {'min': 0.75, 'max': 1.0, 'symbol': '🔴', 'color': '#FF0000'},
    'high': {'min': 0.45, 'max': 0.75, 'symbol': '🟠', 'color': '#FF8C00'},
    'medium': {'min': 0.25, 'max': 0.45, 'symbol': '🟡', 'color': '#FFD700'},
    'low': {'min': 0.0, 'max': 0.25, 'symbol': '🟢', 'color': '#90EE90'},
}

# ============================================================================
# TIPOS DE AMEAÇA
# ============================================================================

THREAT_TYPES = [
    'ransomware', 'trojan', 'wiper', 'dropper',
    'exfiltration', 'c2_communication', 'unknown'
]

# ============================================================================
# LOGGING
# ============================================================================

LOGGING_CONFIG = {
    'log_file': str(LOGS_DIR / 'ransomware_scanner.log'),
    'log_level': 'INFO',
    'format': '%(asctime)s - %(levelname)s - %(message)s',
    'date_format': '%Y-%m-%d %H:%M:%S',
}

# ============================================================================
# QUARENTENA
# ============================================================================

QUARANTINE_CONFIG = {
    'organize_by_type': True,
    'organize_by_date': True,
    'organize_by_risk': True,
    'store_metadata': True,
    'metadata_dir': str(QUARANTINE_DIR / '.metadata'),
}

# ============================================================================
# RELATÓRIOS
# ============================================================================

REPORT_CONFIG = {
    'generate_json': True,
    'generate_pdf': True,
    'generate_charts': True,
    'dpi': 300,
    'charts_format': 'png',
}

# ============================================================================
# PESOS DO SCORE DE RISCO
# ============================================================================

RISK_SCORE_WEIGHTS = {
    'entropy': 0.35,           # 35% - Análise de entropia
    'spike': 0.15,             # 15% - Variação de entropia
    'keywords': 0.25,          # 25% - Palavras-chave de malware
    'extension': 0.25,         # 25% - Extensão suspeita
}

# Validação: pesos devem somar 1.0
assert sum(RISK_SCORE_WEIGHTS.values()) == 1.0, "Risk score weights must sum to 1.0"

# ============================================================================
# VIRUSTOTAL API
# ============================================================================

VIRUSTOTAL_CONFIG = {
    # Insira sua chave de API VirusTotal (https://www.virustotal.com/gui/my-apikey)
    'api_key': os.environ.get('VIRUSTOTAL_API_KEY', ''),
    'base_url': 'https://www.virustotal.com/api/v3',
    'cache_ttl_days': 7,
    'rate_limit_per_minute': 4,    # Limite para conta gratuita
}

# ============================================================================
# CVE DATABASE (NVD)
# ============================================================================

CVE_CONFIG = {
    'nvd_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    'cache_ttl_hours': 24,
    'max_results': 20,
}

# ============================================================================
# BUSCA AVANÇADA DE ARQUIVOS
# ============================================================================

ADVANCED_SEARCH_CONFIG = {
    'exclude_dirs': [
        '.git', '.svn', '.hg',
        'node_modules', '__pycache__', '.tox', '.venv', 'venv', 'env',
        '.idea', '.vscode',
        'quarantine',
    ],
    'max_workers': 4,
}

# ============================================================================
# VALIDAÇÕES
# ============================================================================

def validate_config():
    """Valida configurações globais"""
    errors = []
    
    # Validar diretórios
    for dir_name, directory in [
        ('QUARANTINE_DIR', QUARANTINE_DIR),
        ('LOGS_DIR', LOGS_DIR),
        ('REPORTS_DIR', REPORTS_DIR),
    ]:
        if not directory.exists():
            errors.append(f"{dir_name} does not exist: {directory}")
    
    # Validar threshold
    if not 0 <= SCAN_CONFIG['threat_threshold'] <= 1.0:
        errors.append(f"Invalid threat_threshold: {SCAN_CONFIG['threat_threshold']}")
    
    # Validar pesos
    if sum(RISK_SCORE_WEIGHTS.values()) != 1.0:
        errors.append("Risk score weights must sum to 1.0")
    
    if errors:
        raise ValueError("Configuration validation failed:\n" + "\n".join(errors))
    
    return True

if __name__ == "__main__":
    print("✅ Configuration loaded successfully!")
    validate_config()
    print("✅ All validations passed!")
