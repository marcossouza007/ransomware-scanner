# ============================================================================
# QUARENTENA E SOBRESCRITA SEGURA
# ============================================================================

import os
import shutil
import json
import hashlib
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from config import (
    QUARANTINE_DIR, RISK_LEVELS, SecureOverwriteMethod,
    OVERWRITE_PASSES, QUARANTINE_CONFIG, DEFAULT_OVERWRITE_METHOD
)
from utils import (
    logger, calculate_sha256, get_file_info,
    save_metadata, load_metadata, format_bytes,
    print_success, print_error, print_warning
)

# ============================================================================
# 1. QUARENTENA
# ============================================================================

class QuarantineManager:
    """Gerencia quarentena de arquivos infectados"""
    
    def __init__(self, quarantine_dir: str = str(QUARANTINE_DIR)):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.quarantined_files = []
        self._ensure_subdirs()
        logger.info(f"Quarantine manager initialized: {quarantine_dir}")
    
    def _ensure_subdirs(self):
        """Cria subdirectórios da quarentena"""
        subdirs = [
            'by_type',
            'by_date',
            'by_risk',
            '.metadata'
        ]
        for subdir in subdirs:
            (self.quarantine_dir / subdir).mkdir(parents=True, exist_ok=True)
    
    def _get_risk_category(self, risk_score: float) -> str:
        """Retorna categoria de risco"""
        for category, levels in RISK_LEVELS.items():
            if levels['min'] <= risk_score < levels['max']:
                return category
        return 'low'
    
    def _get_threat_type_dir(self, threat_type: str, extension: str) -> Path:
        """Retorna diretório para tipo de ameaça"""
        ext = extension.lstrip('.') if extension else 'unknown'
        return self.quarantine_dir / 'by_type' / threat_type / ext
    
    def _get_date_dir(self) -> Path:
        """Retorna diretório para data atual"""
        date_str = datetime.now().strftime('%Y-%m-%d')
        return self.quarantine_dir / 'by_date' / date_str
    
    def _get_risk_dir(self, risk_category: str) -> Path:
        """Retorna diretório para nível de risco"""
        return self.quarantine_dir / 'by_risk' / risk_category
    
    def _generate_quarantine_id(self) -> str:
        """Gera ID único para arquivo em quarentena"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_str = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]
        return f"{random_str}_{timestamp}"
    
    def quarantine_file(
        self,
        file_path: str,
        risk_score: float,
        threat_type: str = 'unknown',
        reason: str = 'Suspected ransomware'
    ) -> Optional[Dict]:
        """Move arquivo para quarentena com metadados"""
        try:
            if not os.path.isfile(file_path):
                logger.error(f"File not found: {file_path}")
                print_error(f"Arquivo não encontrado: {file_path}")
                return None
            
            # Gerar ID único
            quarantine_id = self._generate_quarantine_id()
            filename = os.path.basename(file_path)
            name, ext = os.path.splitext(filename)
            
            # Renomear arquivo em quarentena
            quarantine_filename = f"{quarantine_id}_{name}{ext}"
            
            # Criar caminhos em 3 estruturas
            risk_category = self._get_risk_category(risk_score)
            
            type_dir = self._get_threat_type_dir(threat_type, ext)
            date_dir = self._get_date_dir()
            risk_dir = self._get_risk_dir(risk_category)
            
            # Garantir diretórios existem
            for directory in [type_dir, date_dir, risk_dir]:
                directory.mkdir(parents=True, exist_ok=True)
            
            # Mover arquivo para type_dir
            quarantine_path = type_dir / quarantine_filename
            shutil.move(file_path, str(quarantine_path))
            
            # Criar symlinks/cópias em outras estruturas
            try:
                shutil.copy2(str(quarantine_path), str(date_dir / quarantine_filename))
                shutil.copy2(str(quarantine_path), str(risk_dir / quarantine_filename))
            except:
                pass  # Se falhar, pelo menos está em by_type
            
            # Armazenar metadados
            file_info = get_file_info(str(quarantine_path))
            metadata = {
                'quarantine_id': quarantine_id,
                'original_path': file_path,
                'quarantine_path': str(quarantine_path),
                'filename': filename,
                'file_hash': calculate_sha256(file_path) or 'N/A',
                'risk_score': risk_score,
                'risk_category': risk_category,
                'threat_type': threat_type,
                'threat_reason': reason,
                'file_size': os.path.getsize(str(quarantine_path)),
                'quarantined_at': datetime.now().isoformat(),
                'file_info': file_info
            }
            
            # Salvar metadados
            metadata_file = self.quarantine_dir / '.metadata' / f"{quarantine_id}.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            self.quarantined_files.append(metadata)
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            print_success(f"Arquivo em quarentena: {quarantine_path}")
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            print_error(f"Erro ao colocar em quarentena: {e}")
            return None
    
    def restore_file(self, quarantine_id: str, restore_path: str) -> bool:
        """Restaura arquivo da quarentena"""
        try:
            metadata_file = self.quarantine_dir / '.metadata' / f"{quarantine_id}.json"
            if not metadata_file.exists():
                print_error(f"Metadados não encontrados: {quarantine_id}")
                return False
            
            metadata = json.loads(metadata_file.read_text())
            quarantine_path = metadata['quarantine_path']
            
            if not os.path.exists(quarantine_path):
                print_error(f"Arquivo em quarentena não encontrado: {quarantine_path}")
                return False
            
            shutil.copy2(quarantine_path, restore_path)
            logger.info(f"File restored: {quarantine_path} -> {restore_path}")
            print_success(f"Arquivo restaurado: {restore_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error restoring file {quarantine_id}: {e}")
            print_error(f"Erro ao restaurar: {e}")
            return False
    
    def list_quarantined(self) -> List[Dict]:
        """Lista todos os arquivos em quarentena"""
        metadata_dir = self.quarantine_dir / '.metadata'
        if not metadata_dir.exists():
            return []
        
        files = []
        for metadata_file in metadata_dir.glob('*.json'):
            try:
                metadata = json.loads(metadata_file.read_text())
                files.append(metadata)
            except:
                pass
        
        return sorted(files, key=lambda x: x['quarantined_at'], reverse=True)
    
    def generate_quarantine_report(self, output_file: str = 'quarantine_report.json'):
        """Gera relatório de quarentena"""
        from utils import save_json_report
        
        quarantined = self.list_quarantined()
        
        by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        by_type = {}
        
        for item in quarantined:
            by_risk[item['risk_category']] += 1
            threat_type = item['threat_type']
            by_type[threat_type] = by_type.get(threat_type, 0) + 1
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_quarantined': len(quarantined),
            'by_risk': by_risk,
            'by_threat_type': by_type,
            'quarantined_files': quarantined
        }
        
        save_json_report(report, output_file)
        print(f"\n📄 Relatório de Quarentena salvo: {output_file}")
        return report

# ============================================================================
# 2. SOBRESCRITA SEGURA
# ============================================================================

class SecureDeleter:
    """Realiza delete seguro com múltiplos métodos de sobrescrita"""
    
    def __init__(self, method: SecureOverwriteMethod = DEFAULT_OVERWRITE_METHOD):
        self.method = method
        self.deleted_files = []
        logger.info(f"Secure deleter initialized with method: {method.value}")
    
    def _dod_5220_22_pattern(self, iteration: int) -> bytes:
        """Padrão DOD 5220.22-M: zeros, uns, aleatório"""
        if iteration == 0:
            return b'\x00'
        elif iteration == 1:
            return b'\xFF'
        else:
            return bytes([random.randint(0, 255)])
    
    def _schneier_pattern(self, iteration: int) -> bytes:
        """Padrão Schneier (7 passes)"""
        patterns = [
            b'\x00', b'\xFF',  # 0s e 1s
            bytes([random.randint(0, 255)]),  # aleatório
            bytes([random.randint(0, 255)]),  # aleatório
            bytes([random.randint(0, 255)]),  # aleatório
            b'\xAA', b'\x55',  # Alternando
        ]
        return patterns[iteration % len(patterns)]
    
    def _gutmann_pattern(self, iteration: int) -> bytes:
        """Padrão Gutmann (35 passes)"""
        if iteration < 4:
            return bytes([random.randint(0, 255)])
        elif iteration == 4:
            return b'\x55'
        elif iteration == 5:
            return b'\xAA'
        elif iteration < 32:
            return bytes([(iteration - 6) & 0xFF])
        elif iteration == 32:
            return b'\x55'
        elif iteration == 33:
            return b'\xAA'
        else:
            return bytes([random.randint(0, 255)])
    
    def _nist_pattern(self, iteration: int) -> bytes:
        """Padrão NIST (3 passes): zeros, uns, aleatório"""
        if iteration == 0:
            return b'\x00'
        elif iteration == 1:
            return b'\xFF'
        else:
            return bytes([random.randint(0, 255)])
    
    def _get_pattern(self, iteration: int) -> bytes:
        """Retorna padrão baseado no método"""
        if self.method == SecureOverwriteMethod.SIMPLE_ZEROS:
            return b'\x00'
        elif self.method == SecureOverwriteMethod.RANDOM:
            return bytes([random.randint(0, 255)])
        elif self.method == SecureOverwriteMethod.DOD_5220_22:
            return self._dod_5220_22_pattern(iteration)
        elif self.method == SecureOverwriteMethod.SCHNEIER:
            return self._schneier_pattern(iteration)
        elif self.method == SecureOverwriteMethod.GUTMANN:
            return self._gutmann_pattern(iteration)
        elif self.method == SecureOverwriteMethod.NIST:
            return self._nist_pattern(iteration)
        elif self.method == SecureOverwriteMethod.DBAN:
            # Similar ao DOD mas com 4 passes
            patterns = [b'\x00', b'\xFF', b'\xAA', bytes([random.randint(0, 255)])]
            return patterns[iteration % len(patterns)]
        else:
            return bytes([random.randint(0, 255)])
    
    def secure_delete(
        self,
        file_path: str,
        verbose: bool = True
    ) -> bool:
        """Realiza delete seguro do arquivo"""
        try:
            if not os.path.isfile(file_path):
                print_error(f"Arquivo não encontrado: {file_path}")
                return False
            
            file_size = os.path.getsize(file_path)
            num_passes = OVERWRITE_PASSES.get(self.method, 3)
            
            if verbose:
                print(f"\n🔐 Deletando de forma segura: {file_path}")
                print(f"   Método: {self.method.value}")
                print(f"   Passes: {num_passes}")
            
            # Realizar sobrescrita
            with open(file_path, 'ba+') as f:
                for pass_num in range(num_passes):
                    if verbose:
                        print(f"   [PASS {pass_num + 1}/{num_passes}] {self.method.value}...", end='\r')
                    
                    f.seek(0)
                    pattern = self._get_pattern(pass_num)
                    pattern_repeated = pattern * (file_size // len(pattern) + 1)
                    f.write(pattern_repeated[:file_size])
                    f.flush()
                    os.fsync(f.fileno())
            
            if verbose:
                print(f"   ✓ Sobrescrita concluída                    ")
            
            # Deletar arquivo
            os.remove(file_path)
            logger.info(f"File securely deleted: {file_path}")
            print_success(f"Arquivo removido permanentemente: {file_path}")
            
            self.deleted_files.append({
                'path': file_path,
                'size': file_size,
                'method': self.method.value,
                'passes': num_passes,
                'deleted_at': datetime.now().isoformat()
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Error securely deleting file {file_path}: {e}")
            print_error(f"Erro ao deletar: {e}")
            return False
    
    def secure_delete_batch(
        self,
        file_paths: List[str],
        verbose: bool = True
    ) -> Dict:
        """Deleta múltiplos arquivos com segurança"""
        results = {
            'total': len(file_paths),
            'successful': 0,
            'failed': 0,
            'details': []
        }
        
        for idx, file_path in enumerate(file_paths, 1):
            print(f"\n[{idx}/{len(file_paths)}] ", end='')
            if self.secure_delete(file_path, verbose):
                results['successful'] += 1
            else:
                results['failed'] += 1
        
        return results

if __name__ == "__main__":
    print("✅ Quarantine and Secure Delete modules loaded successfully!")
