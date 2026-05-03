# ============================================================================
# SCANNER DE RANSOMWARE - ANÁLISE DE ENTROPIA E DETECÇÃO
# ============================================================================

import os
import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple

from config import (
    SCAN_CONFIG, SUSPICIOUS_EXTENSIONS, THREAT_DATABASE,
    RISK_SCORE_WEIGHTS, THREAT_TYPES
)
from utils import (
    logger, calculate_sha256, get_file_info,
    format_bytes, is_valid_file, get_file_extension
)

# ============================================================================
# 1. ANÁLISE DE ENTROPIA
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calcula entropia Shannon dos dados"""
    if not data:
        return 0
    
    byte_counts = Counter(data)
    total_bytes = len(data)
    entropy = 0
    
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_entropy(
    filename: str,
    block_size: int = SCAN_CONFIG['block_size']
) -> Tuple[float, float, List[float]]:
    """Analisa entropia em blocos de arquivo e detecta picos"""
    entropies = []
    
    try:
        if not is_valid_file(filename):
            return 0, 0, []
        
        with open(filename, 'rb') as f:
            while chunk := f.read(block_size):
                entropies.append(calculate_entropy(chunk))
        
        if not entropies:
            return 0, 0, []
        
        avg_entropy = sum(entropies) / len(entropies)
        
        # Detectar picos de entropia
        spikes = 0
        for i in range(1, len(entropies)):
            if abs(entropies[i] - entropies[i-1]) > 1.0:
                spikes += 1
        
        spike_ratio = spikes / len(entropies) if entropies else 0
        
        logger.info(f"Entropy analysis for {filename}: avg={avg_entropy:.2f}, spike_ratio={spike_ratio:.2f}")
        return avg_entropy, spike_ratio, entropies
        
    except Exception as e:
        logger.error(f"Error analyzing entropy for {filename}: {e}")
        return 0, 0, []

# ============================================================================
# 2. DETECÇÃO DE EXTENSÕES SUSPEITAS
# ============================================================================

def check_extension(filename: str) -> bool:
    """Verifica se arquivo tem extensão suspeita"""
    ext = get_file_extension(filename)
    return ext in SUSPICIOUS_EXTENSIONS

# ============================================================================
# 3. DETECÇÃO DE PALAVRAS-CHAVE
# ============================================================================

def count_keywords(filename: str, threat_db: Dict) -> int:
    """Conta palavras-chave de ameaça no arquivo"""
    hits = 0
    
    try:
        if not is_valid_file(filename):
            return 0
        
        # Limitar leitura a primeiros 1MB
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1024 * 1024).lower()
            
            for category, keywords in threat_db.items():
                for keyword in keywords:
                    hits += content.count(keyword)
        
        if hits > 0:
            logger.info(f"Found {hits} threat keywords in {filename}")
        
        return hits
        
    except Exception as e:
        logger.debug(f"Error counting keywords in {filename}: {e}")
        return 0

# ============================================================================
# 4. CLASSIFICAÇÃO DE AMEAÇA
# ============================================================================

def classify_threat_type(filename: str, keywords_hit: int) -> str:
    """Classifica tipo de ameaça baseado em análise"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1024 * 1024).lower()
        
        # Verificar categorias de ameaça
        for threat_type in THREAT_TYPES:
            if threat_type in THREAT_DATABASE:
                keywords = THREAT_DATABASE[threat_type]
                matches = sum(1 for kw in keywords if kw in content)
                if matches >= 2:
                    return threat_type
        
        return 'unknown'
        
    except:
        return 'unknown'

# ============================================================================
# 5. SCANNER PRINCIPAL
# ============================================================================

class RansomwareScanner:
    """Scanner completo de ransomware"""
    
    def __init__(self, threat_db: Dict = None, threat_threshold: float = 0.5):
        self.threat_db = threat_db or THREAT_DATABASE
        self.threat_threshold = threat_threshold
        self.infected_files = []
        self.scan_results = []
        self.start_time = None
        self.end_time = None
    
    def calculate_risk(
        self,
        filename: str,
        threat_db: Dict = None
    ) -> float:
        """Calcula score de risco geral (0-1)"""
        if threat_db is None:
            threat_db = self.threat_db
        
        if not is_valid_file(filename):
            return 0
        
        try:
            # Análise de entropia
            avg_entropy, spike_ratio, _ = analyze_entropy(filename)
            entropy_score = min(avg_entropy / 8, 1.0)
            spike_score = min(spike_ratio, 1.0)
            
            # Análise de palavras-chave
            keyword_hits = count_keywords(filename, threat_db)
            keyword_score = min(keyword_hits / 10, 1.0)
            
            # Verificar extensão suspeita
            ext_score = 1.0 if check_extension(filename) else 0.0
            
            # Calcular score ponderado
            risk_score = (
                entropy_score * RISK_SCORE_WEIGHTS['entropy'] +
                spike_score * RISK_SCORE_WEIGHTS['spike'] +
                keyword_score * RISK_SCORE_WEIGHTS['keywords'] +
                ext_score * RISK_SCORE_WEIGHTS['extension']
            )
            
            return risk_score
            
        except Exception as e:
            logger.error(f"Error calculating risk for {filename}: {e}")
            return 0
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        enable_virus_detection: bool = False,
    ) -> List[Dict]:
        """Escaneia diretório em busca de ransomware"""
        self.start_time = datetime.now()
        self.infected_files = []
        
        print(f"\n🔍 Iniciando scan em: {directory}")
        print("=" * 80)
        
        if not os.path.isdir(directory):
            logger.error(f"Directory not found: {directory}")
            print(f"❌ Diretório não encontrado: {directory}")
            return []

        # Importar detector de vírus apenas quando solicitado
        virus_detector = None
        if enable_virus_detection:
            try:
                from virus_detector import get_detector
                virus_detector = get_detector()
                print("🦠 Detecção de vírus ativada")
            except Exception as e:
                logger.warning(f"Módulo de detecção de vírus indisponível: {e}")
        
        try:
            if recursive:
                paths = Path(directory).rglob('*')
            else:
                paths = Path(directory).glob('*')
            
            total_files = 0
            for file_path in paths:
                if file_path.is_file():
                    total_files += 1
                    try:
                        risk_score = self.calculate_risk(str(file_path))

                        # Incorporar score de detecção de vírus, se ativado
                        virus_probability = 0.0
                        virus_names: List[str] = []
                        if virus_detector:
                            try:
                                virus_probability = virus_detector.detect_virus_probability(
                                    str(file_path)
                                )
                                virus_names = virus_detector.get_virus_names()
                                # Elevar risk_score se detector de vírus identificar ameaça
                                if virus_probability > 0:
                                    risk_score = min(
                                        risk_score + virus_probability * 0.3, 1.0
                                    )
                            except Exception as e:
                                logger.debug(f"Erro na detecção de vírus para {file_path}: {e}")
                        
                        if risk_score > self.threat_threshold:
                            threat_info = {
                                'path': str(file_path),
                                'risk_score': risk_score,
                                'size': os.path.getsize(str(file_path)),
                                'timestamp': datetime.now().isoformat(),
                                'file_hash': calculate_sha256(str(file_path)),
                                'threat_type': classify_threat_type(str(file_path), 0),
                                'extension': get_file_extension(str(file_path)),
                                'virus_probability': virus_probability,
                                'virus_names': virus_names,
                            }
                            self.infected_files.append(threat_info)
                            print(f"⚠️  [ENCONTRADO] {file_path}")
                            print(f"   └─ Risk Score: {risk_score:.2%}")
                            if virus_names:
                                print(f"   └─ Vírus: {', '.join(virus_names[:3])}")
                    except Exception as e:
                        logger.debug(f"Error processing {file_path}: {e}")
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            print(f"\n✓ Scan concluído: {total_files} arquivos analisados em {duration:.1f}s")
            print(f"🚨 Ameaças encontradas: {len(self.infected_files)}")
            
            logger.info(f"Scan completed: {total_files} files scanned, {len(self.infected_files)} threats found")
            
            return self.infected_files
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
            print(f"❌ Erro durante scan: {e}")
            return []
    
    def generate_report(self, output_file: str = 'ransomware_scan_report.json'):
        """Gera relatório de scan em JSON"""
        from utils import save_json_report
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_threats': len(self.infected_files),
            'scan_duration': (
                (self.end_time - self.start_time).total_seconds()
                if self.start_time and self.end_time else 0
            ),
            'threats': self.infected_files
        }
        
        save_json_report(report, output_file)
        print(f"\n📄 Relatório de Scan salvo: {output_file}")
        return report
    
    def get_statistics(self) -> Dict:
        """Retorna estatísticas do scan"""
        if not self.infected_files:
            return {'total': 0, 'by_risk': {}}
        
        by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_size = 0
        
        for threat in self.infected_files:
            score = threat['risk_score']
            if score > 0.75:
                by_risk['critical'] += 1
            elif score > 0.45:
                by_risk['high'] += 1
            elif score > 0.25:
                by_risk['medium'] += 1
            else:
                by_risk['low'] += 1
            
            total_size += threat['size']
        
        return {
            'total': len(self.infected_files),
            'by_risk': by_risk,
            'total_size': format_bytes(total_size)
        }

if __name__ == "__main__":
    print("✅ Scanner module loaded successfully!")
