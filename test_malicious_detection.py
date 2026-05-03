#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🛡️ Test Suite para Ransomware Scanner
Gera arquivos maliciosos e padrões suspeitos para testar a detecção da ferramenta
"""

import os
import sys
import random
import string
import shutil
from pathlib import Path
from datetime import datetime

# Importar classes do scanner
from scanner import RansomwareScanner
from config import SCAN_CONFIG, MALWARE_KEYWORDS, SUSPICIOUS_EXTENSIONS


class MaliciousTestGenerator:
    """Gera arquivos de teste com padrões maliciosos"""
    
    def __init__(self, test_dir="test_malicious_samples"):
        """
        Inicializa o gerador de testes
        
        Args:
            test_dir: Diretório base para arquivos de teste
        """
        self.test_dir = Path(test_dir)
        self.test_dir.mkdir(exist_ok=True)
        self.scanner = RansomwareScanner()
        self.results = {
            "total_files": 0,
            "detected": 0,
            "not_detected": 0,
            "details": []
        }
    
    def create_high_entropy_file(self, filename, size=1024):
        """
        Cria arquivo com alta entropia (padrão de criptografia)
        
        Args:
            filename: Nome do arquivo
            size: Tamanho em bytes
        """
        filepath = self.test_dir / filename
        print(f"[CRIANDO] Arquivo com alta entropia: {filename}")
        
        # Gera dados altamente entrópicos (aleatórios)
        with open(filepath, 'wb') as f:
            f.write(os.urandom(size))
        
        self.results["total_files"] += 1
        return filepath
    
    def create_malware_keyword_file(self, filename, keywords=None):
        """
        Cria arquivo com palavras-chave de malware
        
        Args:
            filename: Nome do arquivo
            keywords: Lista de keywords de malware
        """
        if keywords is None:
            keywords = ["ransomware", "crypt", "AES", "RSA", "bitcoin", "pay"]
        
        filepath = self.test_dir / filename
        print(f"[CRIANDO] Arquivo com keywords de malware: {filename}")
        
        content = "\n".join([
            "#!/usr/bin/env python",
            "# Malicious ransomware generator",
            "",
        ])
        
        content += "\n".join([f"# {kw}" for kw in keywords])
        content += "\n" + "x = " + "0" * 500  # Adiciona ruído
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        self.results["total_files"] += 1
        return filepath
    
    def create_suspicious_extension_file(self, base_filename, suspicious_ext=".encrypted"):
        """
        Cria arquivo com extensão suspeita
        
        Args:
            base_filename: Nome base do arquivo
            suspicious_ext: Extensão suspeita
        """
        filename = f"{base_filename}{suspicious_ext}"
        filepath = self.test_dir / filename
        print(f"[CRIANDO] Arquivo com extensão suspeita: {filename}")
        
        # Cria arquivo com dados aleatórios e extensão suspeita
        with open(filepath, 'wb') as f:
            f.write(os.urandom(512))
        
        self.results["total_files"] += 1
        return filepath
    
    def create_mixed_threat_file(self, filename):
        """
        Cria arquivo com múltiplos indicadores de ameaça
        
        Args:
            filename: Nome do arquivo
        """
        filepath = self.test_dir / filename
        print(f"[CRIANDO] Arquivo com múltiplos indicadores de ameaça: {filename}")
        
        content = "RANSOMWARE_DETECTED\n"
        content += os.urandom(256).hex() + "\n"
        content += "ENCRYPT " * 50 + "\n"
        content += "DECRYPT " * 50 + "\n"
        content += "BITCOIN_WALLET: 1A1z7agoat" + "0" * 25 + "\n"
        content += "AES_KEY_SIZE_256\n"
        
        with open(filepath, 'w', errors='ignore') as f:
            f.write(content)
        
        self.results["total_files"] += 1
        return filepath
    
    def create_legitimate_file(self, filename):
        """
        Cria arquivo legítimo para validação de falsos positivos
        
        Args:
            filename: Nome do arquivo
        """
        filepath = self.test_dir / filename
        print(f"[CRIANDO] Arquivo legítimo: {filename}")
        
        content = """
        # Arquivo legítimo de teste
        def hello_world():
            print("Hello, World!")
            return True
        
        if __name__ == "__main__":
            result = hello_world()
            print(f"Resultado: {result}")
        """
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        self.results["total_files"] += 1
        return filepath
    
    def create_image_with_data(self, filename):
        """
        Cria arquivo de imagem corrompido (simulando criptografia)
        
        Args:
            filename: Nome do arquivo
        """
        filepath = self.test_dir / filename
        print(f"[CRIANDO] Arquivo de imagem corrompido: {filename}")
        
        # Começa com header PNG válido mas dados corrompidos/encriptados
        png_header = bytes([137, 80, 78, 71, 13, 10, 26, 10])
        
        with open(filepath, 'wb') as f:
            f.write(png_header)
            f.write(os.urandom(2048))  # Dados aleatórios
        
        self.results["total_files"] += 1
        return filepath
    
    def create_document_encrypted(self, filename):
        """
        Cria arquivo de documento com extensão suspeita
        
        Args:
            filename: Nome do arquivo
        """
        filepath = self.test_dir / filename
        print(f"[CRIANDO] Arquivo de documento encriptado: {filename}")
        
        # Simula conteúdo encriptado
        content = os.urandom(1024)
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        self.results["total_files"] += 1
        return filepath
    
    def run_all_tests(self):
        """Executa todos os testes de detecção"""
        print("\n" + "="*80)
        print("🛡️  INICIANDO TESTES DE DETECÇÃO DE MALWARE")
        print("="*80 + "\n")
        
        # Cria diversos tipos de arquivos maliciosos
        print("📁 FASE 1: Criando arquivos de teste...\n")
        
        test_cases = [
            ("high_entropy_1.bin", self.create_high_entropy_file),
            ("high_entropy_2.dat", self.create_high_entropy_file),
            ("malware_keywords.py", self.create_malware_keyword_file),
            ("document.locked", lambda f: self.create_suspicious_extension_file("document", ".locked")),
            ("photo.encrypted", lambda f: self.create_suspicious_extension_file("photo", ".encrypted")),
            ("file.crypto", lambda f: self.create_suspicious_extension_file("file", ".crypto")),
            ("mixed_threat.exe", self.create_mixed_threat_file),
            ("legitimate.py", self.create_legitimate_file),
            ("corrupt.png", self.create_image_with_data),
            ("document.docx.locked", lambda f: self.create_document_encrypted("document.docx.locked")),
        ]
        
        for filename, creator in test_cases:
            if callable(creator):
                try:
                    creator(filename)
                except Exception as e:
                    print(f"❌ Erro ao criar {filename}: {e}")
            else:
                creator()
        
        print("\n" + "="*80)
        print("🔍 FASE 2: Executando Scanner...")
        print("="*80 + "\n")
        
        # Executa o scanner no diretório de testes
        print(f"📂 Varrendo diretório: {self.test_dir}\n")
        
        try:
            detected_threats = self.scanner.scan_directory(
                str(self.test_dir),
                recursive=True
            )
            
            print(f"\n✅ Scanner completou: {len(detected_threats)} ameaças detectadas\n")
            
            # Compila resultados
            self._compile_results(detected_threats)
            
        except Exception as e:
            print(f"❌ Erro ao executar scanner: {e}")
            return False
        
        # Exibe relatório
        self._print_report(detected_threats)
        
        return True
    
    def _compile_results(self, detected_threats):
        """
        Compila resultados dos testes
        
        Args:
            detected_threats: Lista de ameaças detectadas
        """
        detected_files = {t['file_path'] for t in detected_threats}
        
        for i in range(1, self.results["total_files"] + 1):
            # Verifica se o arquivo foi detectado
            found = any(str(d['file_path']).endswith(d['file_path'].split('/')[-1]) 
                       for d in detected_threats)
            
            if found:
                self.results["detected"] += 1
            else:
                self.results["not_detected"] += 1
    
    def _print_report(self, detected_threats):
        """
        Exibe relatório de testes
        
        Args:
            detected_threats: Lista de ameaças detectadas
        """
        print("="*80)
        print("📊 RELATÓRIO DE TESTES")
        print("="*80)
        print(f"\n📈 Resumo:")
        print(f"   Total de arquivos: {self.results['total_files']}")
        print(f"   ✅ Detectados:     {self.results['detected']}")
        print(f"   ❌ Não detectados: {self.results['not_detected']}")
        
        if self.results["total_files"] > 0:
            detection_rate = (self.results["detected"] / self.results["total_files"]) * 100
            print(f"   📊 Taxa de detecção: {detection_rate:.1f}%")
        
        print(f"\n🎯 Ameaças Detectadas ({len(detected_threats)}):\n")
        
        for i, threat in enumerate(detected_threats, 1):
            print(f"   [{i}] {threat['file_name']}")
            print(f"       📍 Caminho: {threat['file_path']}")
            print(f"       ⚠️  Risco: {threat['risk_score']:.2f}")
            print(f"       🏷️  Tipo: {threat['threat_type']}")
            print(f"       📌 Motivos:")
            
            reasons = threat.get('detection_reasons', [])
            for reason in reasons:
                print(f"          • {reason}")
            print()
        
        print("="*80)
        print("✨ Testes Completos!")
        print("="*80 + "\n")
    
    def cleanup(self):
        """Remove arquivos de teste"""
        print("\n🧹 Limpando arquivos de teste...")
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
            print(f"✅ Diretório {self.test_dir} removido")
    
    def create_detailed_report(self, output_file="test_results.txt"):
        """
        Cria relatório detalhado
        
        Args:
            output_file: Nome do arquivo de saída
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(output_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("🛡️  RELATÓRIO DETALHADO DE TESTES - RANSOMWARE SCANNER\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Data/Hora: {timestamp}\n")
            f.write(f"Diretório de testes: {self.test_dir.absolute()}\n\n")
            
            f.write(f"📊 ESTATÍSTICAS:\n")
            f.write(f"   Total de arquivos criados: {self.results['total_files']}\n")
            f.write(f"   Arquivos detectados: {self.results['detected']}\n")
            f.write(f"   Arquivos não detectados: {self.results['not_detected']}\n")
            
            if self.results["total_files"] > 0:
                detection_rate = (self.results["detected"] / self.results["total_files"]) * 100
                f.write(f"   Taxa de sucesso: {detection_rate:.1f}%\n\n")
        
        print(f"📄 Relatório salvo em: {output_file}")


def main():
    """Função principal"""
    print("\n🚀 Inicializando Test Suite do Ransomware Scanner\n")
    
    # Cria gerador de testes
    generator = MaliciousTestGenerator()
    
    try:
        # Executa todos os testes
        success = generator.run_all_tests()
        
        if success:
            # Gera relatório detalhado
            generator.create_detailed_report()
            
            # Pergunta se deseja manter os arquivos de teste
            print("\n⚠️  Deseja manter os arquivos de teste? (s/n): ", end="")
            response = input().strip().lower()
            
            if response != 's':
                generator.cleanup()
            else:
                print(f"✅ Arquivos mantidos em: {generator.test_dir.absolute()}")
        
        return 0
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Testes interrompidos pelo usuário")
        generator.cleanup()
        return 1
    
    except Exception as e:
        print(f"\n❌ Erro fatal: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
