# ============================================================================
# CVE CHECKER - RANSOMWARE SCANNER v2.0
# ============================================================================

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import utils
from config import CVE_CONFIG, BASE_DIR

logger = utils.setup_logger('cve_checker')

# ============================================================================
# CACHE
# ============================================================================

CACHE_FILE = BASE_DIR / 'data' / 'cve_cache.json'
CACHE_TTL_HOURS = CVE_CONFIG.get('cache_ttl_hours', 24)


def _load_cache() -> Dict:
    """Carrega cache local de CVEs"""
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Erro ao carregar cache CVE: {e}")
    return {}


def _save_cache(cache: Dict) -> None:
    """Salva cache local de CVEs"""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.warning(f"Erro ao salvar cache CVE: {e}")


def _is_cache_valid(entry: Dict) -> bool:
    """Verifica se entrada do cache ainda é válida"""
    try:
        cached_at = datetime.fromisoformat(entry.get('cached_at', ''))
        return datetime.now() - cached_at < timedelta(hours=CACHE_TTL_HOURS)
    except Exception:
        return False


# ============================================================================
# SEVERIDADE CVSS
# ============================================================================

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']

_SEVERITY_THRESHOLDS = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 4.0,
    'LOW': 0.1,
    'NONE': 0.0,
}


def _cvss_to_severity(score: float) -> str:
    """Converte score CVSS para nível de severidade"""
    for level, threshold in _SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return level
    return 'NONE'


# ============================================================================
# NVD API
# ============================================================================

def search_cves(keyword: str, severity_filter: Optional[str] = None) -> Dict:
    """
    Busca CVEs no NVD (National Vulnerability Database) relacionadas a um
    keyword (ex: nome de ransomware, extensão de arquivo).

    Args:
        keyword: Palavra-chave para buscar (ex: 'wannacry', '.encrypted')
        severity_filter: Filtrar por severidade mínima ('CRITICAL', 'HIGH', etc.)

    Returns:
        {
            'cves': list[dict],
            'cvss_score': float,
            'severity': str,
            'total_found': int,
            'recommendations': list[str],
            'offline': bool
        }
    """
    if not keyword:
        return _empty_result()

    cache_key = f"{keyword}:{severity_filter or 'ALL'}"
    cache = _load_cache()

    if cache_key in cache and _is_cache_valid(cache[cache_key]):
        logger.info(f"Cache hit para CVE keyword '{keyword}'")
        result = cache[cache_key].copy()
        result['from_cache'] = True
        return result

    try:
        import requests  # noqa: PLC0415

        params = {
            'keywordSearch': keyword,
            'resultsPerPage': CVE_CONFIG.get('max_results', 20),
        }

        response = requests.get(
            CVE_CONFIG['nvd_url'],
            params=params,
            timeout=15,
        )
        response.raise_for_status()

        data = response.json()
        result = _parse_nvd_response(data, severity_filter)
        _store_in_cache(cache, cache_key, result)
        return result

    except ImportError:
        logger.error("Biblioteca 'requests' não instalada")
        return _offline_result(keyword)
    except Exception as e:
        logger.warning(f"Erro ao consultar NVD: {e}")
        return _offline_result(keyword)


def _parse_nvd_response(data: Dict, severity_filter: Optional[str]) -> Dict:
    """Interpreta resposta da API NVD"""
    cves = []
    max_cvss = 0.0

    for vuln in data.get('vulnerabilities', []):
        cve_data = vuln.get('cve', {})
        cve_id = cve_data.get('id', 'N/A')

        # Descrição em inglês
        descriptions = cve_data.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            'Sem descrição disponível',
        )

        # Score CVSS (preferir v3, fallback v2)
        cvss_score = 0.0
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            cvss_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
        elif 'cvssMetricV30' in metrics:
            cvss_score = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore', 0.0)
        elif 'cvssMetricV2' in metrics:
            cvss_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0.0)

        severity = _cvss_to_severity(cvss_score)

        # Aplicar filtro de severidade
        if severity_filter:
            filter_idx = SEVERITY_ORDER.index(severity_filter.upper()) if severity_filter.upper() in SEVERITY_ORDER else len(SEVERITY_ORDER)
            cve_idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
            if cve_idx > filter_idx:
                continue

        if cvss_score > max_cvss:
            max_cvss = cvss_score

        published = cve_data.get('published', '')[:10]
        references = [ref['url'] for ref in cve_data.get('references', [])[:3]]

        cves.append({
            'id': cve_id,
            'description': description[:300],
            'cvss_score': cvss_score,
            'severity': severity,
            'published': published,
            'references': references,
        })

    recommendations = _generate_recommendations(cves)

    return {
        'cves': cves,
        'cvss_score': max_cvss,
        'severity': _cvss_to_severity(max_cvss),
        'total_found': len(cves),
        'recommendations': recommendations,
        'offline': False,
        'from_cache': False,
        'cached_at': datetime.now().isoformat(),
    }


def _generate_recommendations(cves: List[Dict]) -> List[str]:
    """Gera recomendações com base nas CVEs encontradas"""
    if not cves:
        return ['Nenhuma CVE conhecida encontrada para este padrão']

    recs = [
        'Mantenha o sistema operacional e softwares sempre atualizados',
        'Use software antivírus com definições de vírus atualizadas',
        'Faça backup regular de arquivos importantes em local isolado',
    ]

    has_critical = any(c['severity'] == 'CRITICAL' for c in cves)
    has_high = any(c['severity'] == 'HIGH' for c in cves)

    if has_critical:
        recs.insert(0, '🔴 CRÍTICO: Aplique patches de segurança imediatamente')
    elif has_high:
        recs.insert(0, '🟠 ALTO: Atualize sistemas o mais breve possível')

    return recs


def _store_in_cache(cache: Dict, key: str, result: Dict) -> None:
    """Armazena resultado no cache"""
    entry = result.copy()
    entry['cached_at'] = datetime.now().isoformat()
    cache[key] = entry
    _save_cache(cache)


def _empty_result() -> Dict:
    return {
        'cves': [],
        'cvss_score': 0.0,
        'severity': 'NONE',
        'total_found': 0,
        'recommendations': [],
        'offline': False,
        'from_cache': False,
    }


def _offline_result(keyword: str) -> Dict:
    result = _empty_result()
    result['offline'] = True
    result['message'] = (
        f"Não foi possível consultar NVD para '{keyword}'. "
        "Verifique sua conexão com a internet."
    )
    return result


# ============================================================================
# UTILITÁRIOS ADICIONAIS
# ============================================================================

def search_cves_by_extension(extension: str) -> Dict:
    """Busca CVEs relacionadas a uma extensão de arquivo"""
    clean_ext = extension.lstrip('.')
    return search_cves(clean_ext)


def search_cves_by_ransomware(ransomware_name: str,
                               severity_filter: Optional[str] = None) -> Dict:
    """Busca CVEs relacionadas a um tipo específico de ransomware"""
    return search_cves(ransomware_name, severity_filter)


def clear_cache() -> None:
    """Limpa o cache local de CVEs"""
    try:
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
            logger.info("Cache CVE limpo")
    except Exception as e:
        logger.error(f"Erro ao limpar cache CVE: {e}")


def get_cache_stats() -> Dict:
    """Retorna estatísticas do cache de CVEs"""
    cache = _load_cache()
    valid = sum(1 for v in cache.values() if _is_cache_valid(v))
    return {
        'total_entries': len(cache),
        'valid_entries': valid,
        'expired_entries': len(cache) - valid,
        'cache_file': str(CACHE_FILE),
    }


if __name__ == '__main__':
    print("✅ CVE Checker carregado com sucesso!")
