# ============================================================================
# UTILITÁRIOS - RANSOMWARE SCANNER v2.0
# ============================================================================

import os
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from config import (
    LOGS_DIR, LOGGING_CONFIG, QUARANTINE_DIR,
    REPORTS_DIR, CHARTS_DIR
)

# ============================================================================
# LOGGING
# ============================================================================

def setup_logger(name: str = 'ransomware_scanner') -> logging.Logger:
    """Configura logger global"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Handler para arquivo
        fh = logging.FileHandler(LOGGING_CONFIG['log_file'])
        fh.setLevel(logging.INFO)
        
        # Handler para console
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            LOGGING_CONFIG['format'],
            datefmt=LOGGING_CONFIG['date_format']
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
    
    return logger

logger = setup_logger()

# ============================================================================
# HASHING
# ============================================================================

def calculate_sha256(filepath: str) -> str:
    """Calcula SHA256 de um arquivo"""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating SHA256 for {filepath}: {e}")
        return None

def calculate_md5(filepath: str) -> str:
    """Calcula MD5 de um arquivo"""
    try:
        md5_hash = hashlib.md5()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
        return md5_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating MD5 for {filepath}: {e}")
        return None

# ============================================================================
# ARQUIVO E METADADOS
# ============================================================================

def get_file_info(filepath: str) -> Dict[str, Any]:
    """Obtém informações completas de um arquivo"""
    try:
        stat = os.stat(filepath)
        return {
            'path': filepath,
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'permissions': oct(stat.st_mode)[-3:],
        }
    except Exception as e:
        logger.error(f"Error getting file info for {filepath}: {e}")
        return {}

def save_metadata(metadata: Dict[str, Any], metadata_file: str):
    """Salva metadados em JSON"""
    try:
        os.makedirs(os.path.dirname(metadata_file), exist_ok=True)
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        logger.info(f"Metadata saved: {metadata_file}")
    except Exception as e:
        logger.error(f"Error saving metadata: {e}")

def load_metadata(metadata_file: str) -> Dict[str, Any]:
    """Carrega metadados de JSON"""
    try:
        with open(metadata_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading metadata: {e}")
        return {}

# ============================================================================
# VALIDAÇÃO
# ============================================================================

def is_valid_file(filepath: str) -> bool:
    """Valida se arquivo é válido para scan"""
    try:
        return os.path.isfile(filepath) and os.access(filepath, os.R_OK)
    except:
        return False

def is_valid_directory(directory: str) -> bool:
    """Valida se diretório é válido"""
    try:
        return os.path.isdir(directory) and os.access(directory, os.R_OK)
    except:
        return False

def get_file_extension(filepath: str) -> str:
    """Obtém extensão do arquivo"""
    return os.path.splitext(filepath)[1].lower()

def get_file_type_from_content(filepath: str) -> str:
    """Detecta tipo de arquivo pela assinatura mágica (magic bytes)"""
    magic_bytes = {
        b'PK\x03\x04': 'zip',
        b'\x7fELF': 'elf',
        b'\xca\xfe\xba\xbe': 'mach',
        b'MZ': 'pe',
        b'\x89PNG': 'png',
        b'\xff\xd8\xff': 'jpeg',
        b'GIF8': 'gif',
    }
    
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            for magic, ftype in magic_bytes.items():
                if header.startswith(magic):
                    return ftype
    except:
        pass
    
    return 'unknown'

# ============================================================================
# FORMATAÇÃO
# ============================================================================

def format_bytes(bytes_size: int) -> str:
    """Formata tamanho em bytes para formato legível"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} PB"

def format_timestamp(timestamp: str) -> str:
    """Formata timestamp ISO para formato legível"""
    try:
        dt = datetime.fromisoformat(timestamp)
        return dt.strftime('%d/%m/%Y às %H:%M:%S')
    except:
        return timestamp

def format_percentage(value: float, decimals: int = 2) -> str:
    """Formata valor como percentual"""
    return f"{value * 100:.{decimals}f}%"

# ============================================================================
# DIRETÓRIOS
# ============================================================================

def ensure_directory_exists(directory: str) -> bool:
    """Garante que diretório existe, cria se necessário"""
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Error creating directory {directory}: {e}")
        return False

def get_quarantine_subdirs() -> Dict[str, str]:
    """Retorna subdirectórios da quarentena"""
    return {
        'by_type': str(QUARANTINE_DIR / 'by_type'),
        'by_date': str(QUARANTINE_DIR / 'by_date'),
        'by_risk': str(QUARANTINE_DIR / 'by_risk'),
        'metadata': str(QUARANTINE_DIR / '.metadata'),
    }

# ============================================================================
# REPORT
# ============================================================================

def save_json_report(data: Dict[str, Any], filename: str) -> bool:
    """Salva relatório em JSON"""
    try:
        filepath = REPORTS_DIR / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report saved: {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving report: {e}")
        return False

def load_json_report(filename: str) -> Optional[Dict[str, Any]]:
    """Carrega relatório JSON"""
    try:
        filepath = REPORTS_DIR / filename
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading report: {e}")
        return None

# ============================================================================
# MENU
# ============================================================================

def print_header(title: str, width: int = 80):
    """Imprime cabeçalho formatado"""
    print("\n" + "=" * width)
    print(title.center(width))
    print("=" * width)

def print_section(title: str, width: int = 80):
    """Imprime seção formatada"""
    print(f"\n{title}")
    print("-" * len(title))

def print_success(message: str):
    """Imprime mensagem de sucesso"""
    print(f"✅ {message}")

def print_error(message: str):
    """Imprime mensagem de erro"""
    print(f"❌ {message}")

def print_warning(message: str):
    """Imprime mensagem de aviso"""
    print(f"⚠️  {message}")

def print_info(message: str):
    """Imprime mensagem de informação"""
    print(f"ℹ️  {message}")

def get_user_confirmation(prompt: str = "Deseja continuar?") -> bool:
    """Obtém confirmação do usuário"""
    while True:
        response = input(f"\n{prompt} (s/n): ").lower().strip()
        if response in ['s', 'sim', 'yes', 'y']:
            return True
        elif response in ['n', 'não', 'no', 'nao']:
            return False
        else:
            print("Digite 's' para Sim ou 'n' para Não")

def validate_directory(directory: str) -> bool:
    """Alias de is_valid_directory para compatibilidade com main.py."""
    return is_valid_directory(directory)

def format_size(bytes_size: int) -> str:
    """Alias de format_bytes para compatibilidade com main.py."""
    return format_bytes(bytes_size)

def generate_report_summary(threats: list) -> dict:
    """Gera resumo estatístico de ameaças detectadas."""
    total = len(threats)
    by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    by_type: dict = {}
    total_size = 0
    total_score = 0.0

    for threat in threats:
        score = threat.get('risk_score', 0)
        total_score += score
        total_size += threat.get('size', 0)

        if score > 0.75:
            by_risk['critical'] += 1
        elif score > 0.45:
            by_risk['high'] += 1
        elif score > 0.25:
            by_risk['medium'] += 1
        else:
            by_risk['low'] += 1

        threat_type = threat.get('threat_type', 'unknown')
        by_type[threat_type] = by_type.get(threat_type, 0) + 1

    return {
        'total': total,
        'by_risk': by_risk,
        'by_type': by_type,
        'total_size': total_size,
        'average_risk': total_score / total if total else 0.0,
    }

# ============================================================================
# FUNÇÕES AUXILIARES DE BUSCA
# ============================================================================

def expand_search_paths(paths: list) -> list:
    """
    Expande caminhos com wildcards usando pathlib/glob.

    Args:
        paths: Lista de strings de caminhos, podendo conter wildcards.

    Returns:
        Lista de caminhos expandidos como strings.
    """
    expanded = []
    for p in paths:
        path = Path(p)
        if any(c in str(p) for c in ('*', '?', '[')):
            parent = path.parent
            pattern = path.name
            try:
                expanded.extend(str(x) for x in parent.glob(pattern))
            except Exception as exc:
                logger.warning(f"Erro ao expandir caminho '{p}': {exc}")
        else:
            expanded.append(str(p))
    return expanded


def is_package_file(filepath: str) -> bool:
    """
    Detecta se um arquivo é um pacote compactado suportado.

    Args:
        filepath: Caminho do arquivo.

    Returns:
        True se for pacote suportado (.zip, .tar, .tar.gz, .tgz, etc.).
    """
    import zipfile as _zf
    import tarfile as _tf
    p = Path(filepath)
    suffixes = ''.join(p.suffixes).lower()
    package_suffixes = {'.zip', '.tar', '.gz', '.bz2', '.xz', '.tgz'}
    if p.suffix.lower() in package_suffixes:
        return True
    if any(suffixes.endswith(s) for s in ('.tar.gz', '.tar.bz2', '.tar.xz')):
        return True
    # Verificar magic bytes
    try:
        if _zf.is_zipfile(filepath):
            return True
        if _tf.is_tarfile(filepath):
            return True
    except Exception:
        pass
    return False


def get_package_contents(filepath: str) -> list:
    """
    Lista o conteúdo de um arquivo compactado sem extraí-lo.

    Args:
        filepath: Caminho do arquivo de pacote.

    Returns:
        Lista de dicts com 'name' e 'size' de cada entrada, ou lista vazia.
    """
    import zipfile as _zf
    import tarfile as _tf

    contents = []
    try:
        if _zf.is_zipfile(filepath):
            with _zf.ZipFile(filepath, 'r') as zf:
                for info in zf.infolist():
                    contents.append({'name': info.filename, 'size': info.file_size})
            return contents
    except Exception as exc:
        logger.debug(f"Erro ao listar zip {filepath}: {exc}")

    try:
        if _tf.is_tarfile(filepath):
            with _tf.open(filepath, 'r:*') as tf:
                for member in tf.getmembers():
                    contents.append({'name': member.name, 'size': member.size})
            return contents
    except Exception as exc:
        logger.debug(f"Erro ao listar tar {filepath}: {exc}")

    return contents


def normalize_path(filepath: str) -> str:
    """
    Normaliza um caminho para formato portável usando pathlib.

    Args:
        filepath: Caminho a ser normalizado.

    Returns:
        Caminho normalizado como string absoluta.
    """
    return str(Path(filepath).resolve())


def validate_search_criteria(criteria: dict) -> list:
    """
    Valida critérios de busca avançada.

    Args:
        criteria: Dicionário de critérios (pattern, extensions, min_size, etc.).

    Returns:
        Lista de strings de erros de validação (vazia se tudo ok).
    """
    errors = []

    if 'min_size' in criteria and criteria['min_size'] is not None:
        if not isinstance(criteria['min_size'], (int, float)) or criteria['min_size'] < 0:
            errors.append("'min_size' deve ser um número >= 0")

    if 'max_size' in criteria and criteria['max_size'] is not None:
        if not isinstance(criteria['max_size'], (int, float)) or criteria['max_size'] < 0:
            errors.append("'max_size' deve ser um número >= 0")

    if (
        criteria.get('min_size') is not None
        and criteria.get('max_size') is not None
        and criteria['min_size'] > criteria['max_size']
    ):
        errors.append("'min_size' não pode ser maior que 'max_size'")

    for date_key in ('start_date', 'end_date'):
        val = criteria.get(date_key)
        if val is not None:
            try:
                datetime.strptime(val, '%Y-%m-%d')
            except ValueError:
                errors.append(f"'{date_key}' deve estar no formato YYYY-MM-DD, recebido: '{val}'")

    if 'extensions' in criteria and criteria['extensions'] is not None:
        if not isinstance(criteria['extensions'], list):
            errors.append("'extensions' deve ser uma lista de strings")

    return errors


if __name__ == "__main__":
    print("✅ Utils loaded successfully!")
