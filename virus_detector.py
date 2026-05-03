# ============================================================================
# VIRUS DETECTOR - RANSOMWARE SCANNER v2.0
# ============================================================================

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import utils
from config import BASE_DIR
from yara_rules import get_all_rules

logger = utils.setup_logger('virus_detector')

# ============================================================================
# ASSINATURAS DE VÍRUS
# ============================================================================

SIGNATURES_FILE = BASE_DIR / 'data' / 'virus_signatures.json'

_SIGNATURES_CACHE: Dict = {}


def _load_signatures() -> Dict:
    """Carrega base de assinaturas de vírus do arquivo JSON"""
    global _SIGNATURES_CACHE
    if _SIGNATURES_CACHE:
        return _SIGNATURES_CACHE
    try:
        if SIGNATURES_FILE.exists():
            with open(SIGNATURES_FILE, 'r', encoding='utf-8') as f:
                _SIGNATURES_CACHE = json.load(f)
    except Exception as e:
        logger.warning(f"Erro ao carregar assinaturas de vírus: {e}")
    return _SIGNATURES_CACHE


# ============================================================================
# DETECTOR PRINCIPAL
# ============================================================================

class VirusDetector:
    """
    Detecta vírus e malware por assinatura e análise comportamental.

    Atributos:
        _detected_names: Nomes de vírus detectados na última análise.
        _last_result: Resultado completo da última análise.
    """

    READ_LIMIT = 512 * 1024  # Ler até 512 KB para análise

    def __init__(self):
        self._detected_names: List[str] = []
        self._last_result: Dict = {}

    # ------------------------------------------------------------------
    # API PÚBLICA
    # ------------------------------------------------------------------

    def detect_virus_probability(self, file_path: str) -> float:
        """
        Retorna probabilidade de infecção (0.0 – 1.0) do arquivo.

        Args:
            file_path: Caminho completo do arquivo

        Returns:
            Float entre 0.0 (seguro) e 1.0 (infecção quase certa)
        """
        self._detected_names = []
        self._last_result = {}

        if not utils.is_valid_file(file_path):
            return 0.0

        try:
            content = self._read_file(file_path)
            yara_score, yara_names = self._check_yara_rules(content)
            sig_score, sig_names = self._check_signatures(file_path)
            behav_score = self._check_behavioral(content)

            # Score composto: YARA 50 %, assinatura 30 %, comportamento 20 %
            probability = (
                yara_score * 0.50 +
                sig_score * 0.30 +
                behav_score * 0.20
            )
            probability = min(probability, 1.0)

            self._detected_names = list(dict.fromkeys(yara_names + sig_names))
            self._last_result = {
                'file': file_path,
                'probability': probability,
                'yara_score': yara_score,
                'signature_score': sig_score,
                'behavioral_score': behav_score,
                'detected_names': self._detected_names,
            }

            logger.info(
                f"Análise de vírus em {file_path}: probabilidade={probability:.2f}"
            )
            return probability

        except Exception as e:
            logger.error(f"Erro ao analisar vírus em {file_path}: {e}")
            return 0.0

    def get_virus_names(self) -> List[str]:
        """Retorna os nomes de vírus detectados na última chamada."""
        return list(self._detected_names)

    def get_last_result(self) -> Dict:
        """Retorna o resultado completo da última análise."""
        return dict(self._last_result)

    # ------------------------------------------------------------------
    # ANÁLISE YARA
    # ------------------------------------------------------------------

    def _check_yara_rules(self, content: bytes) -> Tuple[float, List[str]]:
        """
        Aplica regras YARA-like ao conteúdo do arquivo.

        Returns:
            (score 0.0-1.0, lista de nomes de regras ativadas)
        """
        rules = get_all_rules()
        total_rules = len(rules)
        if total_rules == 0:
            return 0.0, []

        matched_rules: List[str] = []
        content_lower = content.lower()

        for rule in rules:
            strings = rule.get('strings', [])
            hits = sum(1 for s in strings if s.lower() in content_lower)
            # Ativa a regra se pelo menos 1 string coincidir
            if hits > 0:
                matched_rules.append(rule['name'])

        score = min(len(matched_rules) / max(total_rules * 0.2, 1), 1.0)
        return score, matched_rules

    # ------------------------------------------------------------------
    # ANÁLISE POR ASSINATURA (SHA256 / MD5)
    # ------------------------------------------------------------------

    def _check_signatures(self, file_path: str) -> Tuple[float, List[str]]:
        """
        Verifica hash do arquivo contra base de assinaturas conhecidas.

        Returns:
            (1.0 se encontrado, 0.0 caso contrário), lista de nomes
        """
        sigs = _load_signatures()
        if not sigs:
            return 0.0, []

        sha256 = utils.calculate_sha256(file_path)
        md5 = utils.calculate_md5(file_path)

        known_hashes = sigs.get('hashes', {})

        for hash_val in (sha256, md5):
            if hash_val and hash_val in known_hashes:
                name = known_hashes[hash_val]
                logger.warning(f"Hash conhecido de vírus detectado: {name}")
                return 1.0, [name]

        return 0.0, []

    # ------------------------------------------------------------------
    # ANÁLISE COMPORTAMENTAL
    # ------------------------------------------------------------------

    def _check_behavioral(self, content: bytes) -> float:
        """
        Análise comportamental baseada em strings e padrões suspeitos.

        Returns:
            Score de 0.0 a 1.0 indicando nível de suspeita comportamental.
        """
        indicators = [
            # APIs de modificação de arquivos em massa
            b'FindFirstFile',
            b'FindNextFile',
            b'MoveFileEx',
            b'DeleteFile',
            b'CopyFile',
            # Acesso ao registro do Windows
            b'RegSetValueEx',
            b'RegCreateKey',
            b'HKEY_LOCAL_MACHINE',
            b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            # Redes e C2
            b'WSAStartup',
            b'connect(',
            b'recv(',
            b'send(',
            # Strings de pagamento/resgate
            b'bitcoin',
            b'monero',
            b'tor browser',
            b'.onion',
            b'pay ransom',
            b'ransom payment',
            # Elevação de privilégio
            b'SeDebugPrivilege',
            b'AdjustTokenPrivileges',
            b'IsUserAnAdmin',
        ]

        content_lower = content.lower()
        hits = sum(1 for ind in indicators if ind.lower() in content_lower)
        score = min(hits / max(len(indicators) * 0.25, 1), 1.0)
        return score

    # ------------------------------------------------------------------
    # LEITURA DE ARQUIVO
    # ------------------------------------------------------------------

    def _read_file(self, file_path: str) -> bytes:
        """Lê até READ_LIMIT bytes de um arquivo"""
        with open(file_path, 'rb') as f:
            return f.read(self.READ_LIMIT)


# ============================================================================
# INSTÂNCIA GLOBAL (singleton leve)
# ============================================================================

from typing import Optional

_detector_instance: Optional[VirusDetector] = None


def get_detector() -> VirusDetector:
    """Retorna instância compartilhada do detector de vírus"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = VirusDetector()
    return _detector_instance


def detect_virus_probability(file_path: str) -> float:
    """Atalho para get_detector().detect_virus_probability()"""
    return get_detector().detect_virus_probability(file_path)


def get_virus_names() -> List[str]:
    """Atalho para get_detector().get_virus_names()"""
    return get_detector().get_virus_names()


if __name__ == '__main__':
    print("✅ Virus Detector carregado com sucesso!")
