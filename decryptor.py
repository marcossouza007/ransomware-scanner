# ============================================================================
# DESCRIPTOGRAFIA E RECUPERAÇÃO DE RANSOMWARE
# ============================================================================

import os
import shutil
from datetime import datetime
from typing import Dict, List, Optional

from config import KNOWN_RANSOMWARE_KEYS
from utils import logger, print_success, print_error, print_warning, save_json_report

# ============================================================================
# DESCRIPTOGRAFIA
# ============================================================================

class RansomwareDecryptor:
    """Descriptografa arquivos ransomware com chaves conhecidas"""
    
    def __init__(self, backup_dir: Optional[str] = None):
        self.backup_dir = backup_dir
        self.decrypted_files = []
        self.recovery_attempts = []
        logger.info(f"Decryptor initialized with backup_dir: {backup_dir}")
    
    def attempt_xor_decryption(
        self,
        encrypted_file: str,
        output_file: str,
        key: bytes
    ) -> bool:
        """Tenta descriptografar usando XOR simples"""
        try:
            if not os.path.isfile(encrypted_file):
                print_error(f"Arquivo não encontrado: {encrypted_file}")
                return False
            
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = bytearray()
            key_len = len(key)
            
            for i, byte in enumerate(encrypted_data):
                decrypted_data.append(byte ^ key[i % key_len])
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"XOR decryption successful: {encrypted_file} -> {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"XOR decryption failed: {e}")
            print_error(f"Erro na descriptografia XOR: {e}")
            return False
    
    def attempt_aes_decryption(
        self,
        encrypted_file: str,
        output_file: str,
        key: bytes,
        iv: Optional[bytes] = None
    ) -> bool:
        """Tenta descriptografar usando AES"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            if not os.path.isfile(encrypted_file):
                print_error(f"Arquivo não encontrado: {encrypted_file}")
                return False
            
            with open(encrypted_file, 'rb') as f:
                if iv is None:
                    iv = f.read(16)
                encrypted_data = f.read()
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"AES decryption successful: {encrypted_file} -> {output_file}")
            return True
            
        except ImportError:
            print_warning("pycryptodome não instalado. Instale com: pip install pycryptodome")
            logger.warning("pycryptodome not installed")
            return False
        except Exception as e:
            logger.error(f"AES decryption failed: {e}")
            print_error(f"Erro na descriptografia AES: {e}")
            return False
    
    def attempt_known_decryption(
        self,
        infected_file: str,
        ransomware_type: str = 'wannacry'
    ) -> bool:
        """Tenta descriptografia com chave conhecida"""
        if ransomware_type not in KNOWN_RANSOMWARE_KEYS:
            print_error(f"Chave desconhecida para: {ransomware_type}")
            logger.warning(f"Unknown key for ransomware type: {ransomware_type}")
            return False
        
        key = KNOWN_RANSOMWARE_KEYS[ransomware_type]
        output_file = infected_file + '.decrypted'
        
        print(f"\n🔐 Tentando descriptografar com {ransomware_type}...")
        
        success = self.attempt_xor_decryption(infected_file, output_file, key)
        
        if success:
            print_success(f"Descriptografia bem-sucedida!")
            self.decrypted_files.append({
                'original': infected_file,
                'decrypted': output_file,
                'method': 'known_key',
                'ransomware_type': ransomware_type,
                'timestamp': datetime.now().isoformat()
            })
            
            logger.info(f"Successfully decrypted {infected_file} with {ransomware_type} key")
            return True
        else:
            print_warning(f"Descriptografia falhou para {ransomware_type}")
            logger.info(f"Decryption with {ransomware_type} key failed")
            return False
    
    def recover_from_backup(
        self,
        infected_file: str,
        backup_file: str
    ) -> bool:
        """Recupera arquivo do backup"""
        try:
            if not os.path.exists(backup_file):
                print_error(f"Backup não encontrado: {backup_file}")
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            recovery_file = infected_file + '.recovered'
            shutil.copy2(backup_file, recovery_file)
            
            print_success(f"Arquivo recuperado: {recovery_file}")
            
            self.decrypted_files.append({
                'original': infected_file,
                'recovered': recovery_file,
                'method': 'backup_restore',
                'timestamp': datetime.now().isoformat()
            })
            
            logger.info(f"File recovered from backup: {infected_file} -> {recovery_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error recovering from backup: {e}")
            print_error(f"Erro ao recuperar do backup: {e}")
            return False
    
    def attempt_all_keys(
        self,
        infected_file: str,
        stop_on_success: bool = True
    ) -> bool:
        """Tenta todos os tipos de ransomware conhecidos"""
        print(f"\n🔑 Tentando todos os tipos de ransomware conhecidos...")
        
        for ransomware_type in KNOWN_RANSOMWARE_KEYS.keys():
            if self.attempt_known_decryption(infected_file, ransomware_type):
                if stop_on_success:
                    return True
        
        print_warning(f"Nenhuma chave funcionou para {infected_file}")
        return False
    
    def generate_recovery_report(
        self,
        output_file: str = 'recovery_report.json'
    ) -> Dict:
        """Gera relatório de recuperação"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_recovered': len(self.decrypted_files),
            'recovered_files': self.decrypted_files
        }
        
        save_json_report(report, output_file)
        print(f"\n📄 Relatório de Recuperação salvo: {output_file}")
        logger.info(f"Recovery report generated: {output_file}")
        
        return report

if __name__ == "__main__":
    print("✅ Decryptor module loaded successfully!")
