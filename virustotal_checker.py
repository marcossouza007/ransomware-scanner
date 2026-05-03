# ============================================================================
# VIRUSTOTAL CHECKER - RANSOMWARE SCANNER v2.0
# ============================================================================

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import utils
from config import VIRUSTOTAL_CONFIG, BASE_DIR

logger = utils.setup_logger('virustotal_checker')

# ============================================================================
# CACHE
# ============================================================================

CACHE_FILE = BASE_DIR / 'data' / 'virustotal_cache.json'
CACHE_TTL_DAYS = VIRUSTOTAL_CONFIG.get('cache_ttl_days', 7)


def _load_cache() -> Dict:
    """Carrega cache local do VirusTotal"""
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Erro ao carregar cache VirusTotal: {e}")
    return {}


def _save_cache(cache: Dict) -> None:
    """Salva cache local do VirusTotal"""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.warning(f"Erro ao salvar cache VirusTotal: {e}")


def _is_cache_valid(entry: Dict) -> bool:
    """Verifica se entrada do cache ainda é válida"""
    try:
        cached_at = datetime.fromisoformat(entry.get('cached_at', ''))
        return datetime.now() - cached_at < timedelta(days=CACHE_TTL_DAYS)
    except Exception:
        return False


# ============================================================================
# VIRUSTOTAL API
# ============================================================================

def check_hash_virustotal(sha256: str) -> Dict:
    """
    Verifica hash SHA256 contra o banco de dados VirusTotal.

    Args:
        sha256: Hash SHA256 do arquivo

    Returns:
        {
            'detected': bool,
            'malware_names': list[str],
            'score': int (0-100),
            'engines_detected': int,
            'engines_total': int,
            'permalink': str,
            'offline': bool
        }
    """
    if not sha256:
        return _empty_result()

    # Checar cache primeiro
    cache = _load_cache()
    if sha256 in cache and _is_cache_valid(cache[sha256]):
        logger.info(f"Cache hit para hash {sha256[:16]}...")
        result = cache[sha256].copy()
        result['from_cache'] = True
        return result

    api_key = VIRUSTOTAL_CONFIG.get('api_key', '')
    if not api_key:
        logger.warning("VirusTotal API key não configurada – modo offline")
        return _offline_result(sha256)

    try:
        import requests  # noqa: PLC0415

        url = f"{VIRUSTOTAL_CONFIG['base_url']}/files/{sha256}"
        headers = {'x-apikey': api_key}

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            result = _empty_result()
            result['message'] = 'Hash não encontrado no VirusTotal'
            _store_in_cache(cache, sha256, result)
            return result

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit atingido")
            return _rate_limited_result()

        response.raise_for_status()

        data = response.json()
        result = _parse_vt_response(data)
        _store_in_cache(cache, sha256, result)
        return result

    except ImportError:
        logger.error("Biblioteca 'requests' não instalada")
        return _offline_result(sha256)
    except Exception as e:
        logger.error(f"Erro ao consultar VirusTotal: {e}")
        return _offline_result(sha256)


def _parse_vt_response(data: Dict) -> Dict:
    """Interpreta resposta da API VirusTotal v3"""
    try:
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        results = attrs.get('last_analysis_results', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values()) or 1

        malware_names: List[str] = []
        for engine, info in results.items():
            if info.get('category') in ('malicious', 'suspicious'):
                name = info.get('result')
                if name and name not in malware_names:
                    malware_names.append(name)

        engines_detected = malicious + suspicious
        score = int((engines_detected / total) * 100)

        return {
            'detected': engines_detected > 0,
            'malware_names': malware_names[:10],
            'score': score,
            'engines_detected': engines_detected,
            'engines_total': total,
            'permalink': data.get('data', {}).get('links', {}).get('self', ''),
            'offline': False,
            'from_cache': False,
            'cached_at': datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Erro ao interpretar resposta VirusTotal: {e}")
        return _empty_result()


def _store_in_cache(cache: Dict, sha256: str, result: Dict) -> None:
    """Armazena resultado no cache"""
    entry = result.copy()
    entry['cached_at'] = datetime.now().isoformat()
    cache[sha256] = entry
    _save_cache(cache)


def _empty_result() -> Dict:
    return {
        'detected': False,
        'malware_names': [],
        'score': 0,
        'engines_detected': 0,
        'engines_total': 0,
        'permalink': '',
        'offline': False,
        'from_cache': False,
    }


def _offline_result(sha256: str) -> Dict:
    result = _empty_result()
    result['offline'] = True
    result['message'] = 'Modo offline – API key não disponível ou sem conexão'
    return result


def _rate_limited_result() -> Dict:
    result = _empty_result()
    result['offline'] = True
    result['message'] = 'Rate limit atingido – tente novamente em 60 segundos'
    return result


# ============================================================================
# UTILITÁRIOS ADICIONAIS
# ============================================================================

def check_file_virustotal(filepath: str) -> Dict:
    """
    Calcula SHA256 e verifica arquivo contra VirusTotal.

    Args:
        filepath: Caminho do arquivo

    Returns:
        Resultado da verificação VirusTotal
    """
    sha256 = utils.calculate_sha256(filepath)
    if not sha256:
        return _empty_result()
    return check_hash_virustotal(sha256)


def clear_cache() -> None:
    """Limpa o cache local do VirusTotal"""
    try:
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
            logger.info("Cache VirusTotal limpo")
    except Exception as e:
        logger.error(f"Erro ao limpar cache VirusTotal: {e}")


def get_cache_stats() -> Dict:
    """Retorna estatísticas do cache VirusTotal"""
    cache = _load_cache()
    valid = sum(1 for v in cache.values() if _is_cache_valid(v))
    return {
        'total_entries': len(cache),
        'valid_entries': valid,
        'expired_entries': len(cache) - valid,
        'cache_file': str(CACHE_FILE),
    }


if __name__ == '__main__':
    print("✅ VirusTotal Checker carregado com sucesso!")
