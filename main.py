# ============================================================================
# RANSOMWARE SCANNER & RECOVERY TOOL v2.0 - MAIN
# ============================================================================

import os
import sys
from datetime import datetime

import config
import utils
from scanner import RansomwareScanner
from quarantine import QuarantineManager, SecureDeleter
from decryptor import RansomwareDecryptor
from pdf_report import PDFReportGenerator

logger = utils.setup_logger('main')

# ============================================================================
# INTERFACE CLI
# ============================================================================

class RansomwareScannerCLI:
    """Interface CLI para o Ransomware Scanner"""

    def __init__(self):
        self.scanner = RansomwareScanner(
            threat_db=config.THREAT_DATABASE,
            threat_threshold=config.SCAN_CONFIG['threat_threshold']
        )
        self.quarantine = QuarantineManager()
        self.decryptor = RansomwareDecryptor()
        self.pdf_gen = PDFReportGenerator()
        self.threats = []
        self.logger = logger

    def show_banner(self):
        """Exibe banner da aplicação"""
        print("\n" + "="*80)
        print("🛡️  RANSOMWARE SCANNER & RECOVERY TOOL v2.0")
        print("="*80)
        print(f"Iniciado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}")
        print("="*80)

    def show_menu(self):
        """Exibe menu principal"""
        print("\n📋 Menu Principal:\n")
        print("1. 🔍 Escanear Diretório")
        print("2. 📋 Ver Ameaças Detectadas")
        print("3. 🔐 Tentar Recuperação")
        print("4. 🔒 Gerenciar Quarentena")
        print("5. 📄 Gerar Relatórios PDF")
        print("6. 📊 Ver Estatísticas")
        print("7. ⚙️  Configurações")
        print("8. ✖️  Sair")
        print("\n" + "-"*80)

    def scan_directory(self):
        """Opção 1: Escanear Diretório"""
        print("\n🔍 ESCANEAR DIRETÓRIO")
        directory = input("\nDigite o caminho do diretório (padrão: ./): ").strip() or "./"
        
        if not utils.validate_directory(directory):
            print(f"❌ Erro: Diretório inválido: {directory}")
            self.logger.error(f"Tentativa de scan em diretório inválido: {directory}")
            return
        
        recursive = input("Scan recursivo? (s/n, padrão: s): ").lower() != 'n'
        
        self.threats = self.scanner.scan_directory(directory, recursive=recursive)
        self.scanner.generate_report('scan_report.json')
        
        input("\nPressione ENTER para continuar...")

    def view_threats(self):
        """Opção 2: Ver Ameaças Detectadas"""
        if not self.threats:
            print("\n📋 Nenhuma ameaça detectada ainda. Execute um scan primeiro.")
            input("Pressione ENTER para continuar...")
            return
        
        print("\n📋 AMEAÇAS DETECTADAS:\n")
        print("="*80)
        
        for idx, threat in enumerate(self.threats, 1):
            risk_score = threat.get('risk_score', 0)
            if risk_score > 0.75:
                risk_icon = "🔴 CRÍTICO"
            elif risk_score > 0.45:
                risk_icon = "🟠 ALTO"
            elif risk_score > 0.25:
                risk_icon = "🟡 MÉDIO"
            else:
                risk_icon = "🟢 BAIXO"
            
            print(f"\n{idx}. {threat['path']}")
            print(f"   ├─ Risk Score: {risk_score:.2%} ({risk_icon})")
            print(f"   ├─ Tamanho: {utils.format_size(threat.get('size', 0))}")
            print(f"   ├─ Tipo: {threat.get('threat_type', 'unknown')}")
            print(f"   └─ Hash: {threat.get('file_hash', 'N/A')[:16]}...")
        
        print("\n" + "="*80)
        input("Pressione ENTER para continuar...")

    def attempt_recovery(self):
        """Opção 3: Tentar Recuperação"""
        if not self.threats:
            print("\n❌ Nenhuma ameaça detectada. Execute um scan primeiro.")
            input("Pressione ENTER para continuar...")
            return
        
        print("\n🔐 TENTAR RECUPERAÇÃO\n")
        print("Ransomware types disponíveis:")
        for idx, key in enumerate(config.KNOWN_RANSOMWARE_KEYS.keys(), 1):
            print(f"{idx}. {key.upper()}")
        
        choice = input("\nEscolha o tipo (número ou 0 para tentar todos): ").strip()
        
        types_to_try = []
        if choice == '0':
            types_to_try = list(config.KNOWN_RANSOMWARE_KEYS.keys())
        elif choice.isdigit() and 0 < int(choice) <= len(config.KNOWN_RANSOMWARE_KEYS):
            types_to_try = [list(config.KNOWN_RANSOMWARE_KEYS.keys())[int(choice)-1]]
        else:
            print("❌ Opção inválida")
            return
        
        for threat in self.threats:
            file_path = threat['path']
            print(f"\nProcessando: {file_path}")
            
            for ransom_type in types_to_try:
                if self.decryptor.attempt_known_decryption(file_path, ransom_type):
                    print(f"✅ Descriptografia bem-sucedida com {ransom_type}!")
                    break
        
        self.decryptor.generate_recovery_report('recovery_report.json')
        input("\nPressione ENTER para continuar...")

    def manage_quarantine(self):
        """Opção 4: Gerenciar Quarentena"""
        while True:
            print("\n🔒 GERENCIAR QUARENTENA\n")
            print("1. 📋 Listar arquivos em quarentena")
            print("2. 📁 Colocar ameaças em quarentena")
            print("3. 🔄 Restaurar arquivo")
            print("4. 🗑️  Deletar com segurança")
            print("5. ⬅️  Voltar")
            
            choice = input("\nEscolha uma opção: ").strip()
            
            if choice == '1':
                files = self.quarantine.list_quarantined()
                if not files:
                    print("\n❌ Nenhum arquivo em quarentena")
                else:
                    print(f"\n📋 {len(files)} arquivo(s) em quarentena:\n")
                    for f in files[:10]:
                        print(f"• {f['original_name']} ({f['risk_category']})")
                input("\nPressione ENTER para continuar...")
            
            elif choice == '2':
                if not self.threats:
                    print("❌ Nenhuma ameaça detectada")
                else:
                    print(f"\nEncontrando {len(self.threats)} ameaças...")
                    for threat in self.threats:
                        self.quarantine.quarantine_file(
                            threat['path'],
                            risk_score=threat.get('risk_score', 0),
                            threat_type=threat.get('threat_type', 'unknown'),
                            threat_reason='Ransomware detectado pelo scanner'
                        )
                    print("✅ Ameaças colocadas em quarentena")
                input("\nPressione ENTER para continuar...")
            
            elif choice == '3':
                q_id = input("\nDigite o ID da quarentena para restaurar: ").strip()
                if self.quarantine.restore_from_quarantine(q_id):
                    print("✅ Arquivo restaurado")
                else:
                    print("❌ Erro ao restaurar")
                input("\nPressione ENTER para continuar...")
            
            elif choice == '4':
                files = self.quarantine.list_quarantined()
                if files:
                    print(f"\n🗑️  {len(files)} arquivo(s) para deletar com segurança")
                    confirm = input("Confirmar? (s/n): ").lower()
                    if confirm == 's':
                        eraser = SecureDeleter(config.DEFAULT_OVERWRITE_METHOD)
                        for f in files:
                            eraser.secure_delete(f['quarantine_path'])
                        print("✅ Deletados com segurança")
                input("\nPressione ENTER para continuar...")
            
            elif choice == '5':
                break

    def generate_reports(self):
        """Opção 5: Gerar Relatórios PDF"""
        if not self.threats:
            print("\n❌ Nenhuma ameaça detectada. Execute um scan primeiro.")
            input("Pressione ENTER para continuar...")
            return
        
        print("\n📄 GERANDO RELATÓRIOS PDF...\n")
        
        self.pdf_gen.generate_scan_report(self.threats, 'scan_report.pdf')
        
        quarantine_files = self.quarantine.list_quarantined()
        if quarantine_files:
            self.quarantine.generate_quarantine_report('quarantine_report.json')
        
        if self.decryptor.decrypted_files:
            self.decryptor.generate_recovery_report('recovery_report.json')
        
        print("\n✅ Relatórios gerados em ./reports/")
        input("Pressione ENTER para continuar...")

    def show_statistics(self):
        """Opção 6: Ver Estatísticas"""
        if not self.threats:
            print("\n📊 Nenhuma ameaça detectada ainda.")
            input("Pressione ENTER para continuar...")
            return
        
        print("\n📊 ESTATÍSTICAS\n")
        summary = utils.generate_report_summary(self.threats)
        
        print(f"Total de Ameaças: {summary['total']}")
        print(f"\nPor Risco:")
        print(f"  🔴 Crítico: {summary['by_risk']['critical']}")
        print(f"  🟠 Alto: {summary['by_risk']['high']}")
        print(f"  🟡 Médio: {summary['by_risk']['medium']}")
        print(f"  🟢 Baixo: {summary['by_risk']['low']}")
        print(f"\nPor Tipo:")
        for threat_type, count in summary['by_type'].items():
            print(f"  • {threat_type}: {count}")
        print(f"\nTamanho Total: {utils.format_size(summary['total_size'])}")
        print(f"Risk Médio: {summary['average_risk']:.2%}")
        
        input("\nPressione ENTER para continuar...")

    def show_settings(self):
        """Opção 7: Configurações"""
        print("\n⚙️  CONFIGURAÇÕES\n")
        print(f"Threshold de Risco: {config.SCAN_CONFIG['threat_threshold']}")
        print(f"Método de Sobrescrita: {config.DEFAULT_OVERWRITE_METHOD.value}")
        print(f"Diretório de Quarentena: {config.QUARANTINE_DIR}")
        print(f"Log Level: {config.LOGGING_CONFIG['log_level']}")
        print(f"\nExtensões Suspeitas: {len(config.SUSPICIOUS_EXTENSIONS)}")
        print(f"Palavras-chave de Ameaça: {len(config.THREAT_DATABASE)}")
        
        input("\nPressione ENTER para continuar...")

    def run(self):
        """Executa a aplicação"""
        self.show_banner()
        
        while True:
            self.show_menu()
            choice = input("Escolha uma opção: ").strip()
            
            if choice == '1':
                self.scan_directory()
            elif choice == '2':
                self.view_threats()
            elif choice == '3':
                self.attempt_recovery()
            elif choice == '4':
                self.manage_quarantine()
            elif choice == '5':
                self.generate_reports()
            elif choice == '6':
                self.show_statistics()
            elif choice == '7':
                self.show_settings()
            elif choice == '8':
                print("\n👋 Encerrando...")
                self.logger.info("Aplicação encerrada")
                break
            else:
                print("❌ Opção inválida!")


# ============================================================================
# PONTO DE ENTRADA
# ============================================================================

if __name__ == '__main__':
    try:
        cli = RansomwareScannerCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Aplicação interrompida pelo usuário")
        logger.info("Aplicação interrompida pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erro fatal: {e}")
        logger.critical(f"Erro fatal: {e}", exc_info=True)
        sys.exit(1)
