# ============================================================================
# YARA RULES - RANSOMWARE SCANNER v2.0
# Regras YARA-like implementadas como dicionários Python
# ============================================================================

from typing import Dict, List

# ============================================================================
# DEFINIÇÃO DAS REGRAS
# ============================================================================

YARA_RULES: List[Dict] = [
    # ------------------------------------------------------------------
    # RANSOMWARE
    # ------------------------------------------------------------------
    {
        'name': 'Ransomware_Generic',
        'category': 'ransomware',
        'severity': 'HIGH',
        'strings': [
            b'YOUR FILES HAVE BEEN ENCRYPTED',
            b'your files are encrypted',
            b'All of your files have been',
            b'HOW TO RECOVER',
            b'HOW_TO_DECRYPT',
            b'DECRYPT_INSTRUCTION',
            b'RESTORE_FILES',
            b'README_FOR_DECRYPT',
        ],
        'description': 'Strings genéricas de nota de resgate de ransomware',
    },
    {
        'name': 'WannaCry',
        'category': 'ransomware',
        'severity': 'CRITICAL',
        'strings': [
            b'WannaCry',
            b'wanna_cry',
            b'WannaDecryptor',
            b'tasksche.exe',
            b'.WNCRY',
            b'WANACRY!',
        ],
        'description': 'Assinatura do ransomware WannaCry',
    },
    {
        'name': 'Petya_NotPetya',
        'category': 'ransomware',
        'severity': 'CRITICAL',
        'strings': [
            b'Petya',
            b'NotPetya',
            b'GoldenEye',
            b'MBR locker',
            b'chkdsk',
        ],
        'description': 'Assinatura da família Petya/NotPetya',
    },
    {
        'name': 'LockBit',
        'category': 'ransomware',
        'severity': 'CRITICAL',
        'strings': [
            b'LockBit',
            b'LOCKBIT',
            b'.lockbit',
            b'Lockbit_Ransomware',
        ],
        'description': 'Assinatura do ransomware LockBit',
    },
    {
        'name': 'Clop_Ransomware',
        'category': 'ransomware',
        'severity': 'CRITICAL',
        'strings': [
            b'Cl0p',
            b'CLOP',
            b'.clop',
            b'ClopReadMe',
        ],
        'description': 'Assinatura do ransomware Clop',
    },
    {
        'name': 'BlackCat_ALPHV',
        'category': 'ransomware',
        'severity': 'CRITICAL',
        'strings': [
            b'BlackCat',
            b'ALPHV',
            b'.blackcat',
            b'RECOVER-',
        ],
        'description': 'Assinatura do ransomware BlackCat/ALPHV',
    },

    # ------------------------------------------------------------------
    # TROJANS E BACKDOORS
    # ------------------------------------------------------------------
    {
        'name': 'Trojan_Generic',
        'category': 'trojan',
        'severity': 'HIGH',
        'strings': [
            b'CreateRemoteThread',
            b'VirtualAllocEx',
            b'WriteProcessMemory',
            b'NtCreateThreadEx',
            b'RtlCreateUserThread',
        ],
        'description': 'Chamadas de API suspeitas usadas em injeção de processos',
    },
    {
        'name': 'Backdoor_Shell',
        'category': 'backdoor',
        'severity': 'HIGH',
        'strings': [
            b'cmd.exe /c',
            b'powershell -enc',
            b'powershell -nop',
            b'/bin/bash -i',
            b'bash -c',
            b'nc -e /bin/sh',
        ],
        'description': 'Shells remotas e execução de comandos suspeita',
    },

    # ------------------------------------------------------------------
    # EXFILTRAÇÃO DE DADOS
    # ------------------------------------------------------------------
    {
        'name': 'Data_Exfiltration',
        'category': 'exfiltration',
        'severity': 'HIGH',
        'strings': [
            b'password',
            b'credentials',
            b'credit_card',
            b'social_security',
            b'UPLOAD',
            b'FTP',
            b'exfil',
        ],
        'description': 'Indicadores de possível exfiltração de dados',
    },

    # ------------------------------------------------------------------
    # DOWNLOADERS / DROPPERS
    # ------------------------------------------------------------------
    {
        'name': 'Downloader_Generic',
        'category': 'dropper',
        'severity': 'MEDIUM',
        'strings': [
            b'URLDownloadToFile',
            b'WinInet',
            b'InternetOpenUrl',
            b'HttpSendRequest',
            b'wget ',
            b'curl ',
        ],
        'description': 'Funções de download suspeitas',
    },

    # ------------------------------------------------------------------
    # CRIPTOGRAFIA SUSPEITA
    # ------------------------------------------------------------------
    {
        'name': 'Crypto_Usage',
        'category': 'crypto',
        'severity': 'MEDIUM',
        'strings': [
            b'AES_set_encrypt_key',
            b'EVP_EncryptInit',
            b'CryptEncrypt',
            b'BCryptEncrypt',
            b'RSA_public_encrypt',
        ],
        'description': 'Uso de funções de criptografia (pode indicar ransomware)',
    },
]

# ============================================================================
# ACESSO ÀS REGRAS
# ============================================================================

def get_all_rules() -> List[Dict]:
    """Retorna todas as regras YARA-like"""
    return YARA_RULES


def get_rules_by_category(category: str) -> List[Dict]:
    """Retorna regras filtradas por categoria"""
    return [r for r in YARA_RULES if r['category'] == category]


def get_rules_by_severity(severity: str) -> List[Dict]:
    """Retorna regras filtradas por severidade"""
    return [r for r in YARA_RULES if r['severity'] == severity.upper()]


def get_rule_names() -> List[str]:
    """Retorna nomes de todas as regras"""
    return [r['name'] for r in YARA_RULES]


if __name__ == '__main__':
    print(f"✅ YARA Rules carregadas: {len(YARA_RULES)} regras")
