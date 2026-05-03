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
from file_search import AdvancedFileSearch, print_results_table

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
        print("─"*40)
        print("9. 🔎 Busca Avançada de Arquivos")
        print("10. 📁 Listar Diretórios e Estrutura")
        print("11. 📦 Listar e Escanear Pacotes")
        print("12. 🎯 Scan Customizado")
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
                        print(f"• {f['filename']} ({f['risk_category']})")
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
                            reason='Ransomware detectado pelo scanner'
                        )
                    print("✅ Ameaças colocadas em quarentena")
                input("\nPressione ENTER para continuar...")
            
            elif choice == '3':
                q_id = input("\nDigite o ID da quarentena para restaurar: ").strip()
                restore_path = input("Digite o caminho para restaurar o arquivo: ").strip()
                if self.quarantine.restore_file(q_id, restore_path):
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
                        deleter = SecureDeleter(config.DEFAULT_OVERWRITE_METHOD)
                        for f in files:
                            deleter.secure_delete(f['quarantine_path'])
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

    def advanced_file_search(self):
        """Opção 9: Busca Avançada de Arquivos"""
        print("\n🔎 BUSCA AVANÇADA DE ARQUIVOS\n")
        print("Tipo de busca:")
        print("1. Por padrão/extensão")
        print("2. Por tamanho")
        print("3. Por data de modificação")
        print("4. Por nome de arquivo")

        choice = input("\nEscolha (1-4): ").strip()

        directory = input("Diretório de busca (padrão: ./): ").strip() or "./"
        directory = utils.normalize_path(directory)
        if not utils.is_valid_directory(directory):
            print(f"❌ Diretório inválido: {directory}")
            input("Pressione ENTER para continuar...")
            return

        recursive = input("Recursivo? (s/n, padrão: s): ").lower() != 'n'
        searcher = AdvancedFileSearch()

        if choice == '1':
            raw = input("Extensão(ões) separadas por vírgula (ex: .exe,.dll) ou padrão glob (ex: malware*): ").strip()
            if ',' in raw or not raw.startswith('.'):
                # Múltiplas extensões ou padrão glob
                if ',' in raw:
                    exts = [e.strip() for e in raw.split(',')]
                    results = searcher.search_by_extension(exts, directory, recursive)
                else:
                    results = searcher.search_by_pattern(raw, directory, recursive)
            else:
                results = searcher.search_by_extension([raw], directory, recursive)
            print_results_table(results, "Resultados por Padrão/Extensão")

        elif choice == '2':
            min_mb = input("Tamanho mínimo em MB (deixe em branco para sem limite): ").strip()
            max_mb = input("Tamanho máximo em MB (deixe em branco para sem limite): ").strip()
            min_bytes = int(float(min_mb) * 1024 * 1024) if min_mb else None
            max_bytes = int(float(max_mb) * 1024 * 1024) if max_mb else None
            results = searcher.search_by_size(min_bytes, max_bytes, directory, recursive)
            print_results_table(results, "Resultados por Tamanho")

        elif choice == '3':
            start_date = input("Data inicial (YYYY-MM-DD, deixe em branco para sem limite): ").strip() or None
            end_date = input("Data final (YYYY-MM-DD, deixe em branco para sem limite): ").strip() or None
            results = searcher.search_by_date(start_date, end_date, directory, recursive)
            print_results_table(results, "Resultados por Data")

        elif choice == '4':
            pattern = input("Padrão de nome de arquivo (ex: config*, *.bak): ").strip()
            results = searcher.search_by_filename(pattern, directory, recursive)
            print_results_table(results, "Resultados por Nome")

        else:
            print("❌ Opção inválida")
            input("Pressione ENTER para continuar...")
            return

        input("\nPressione ENTER para continuar...")

    def list_directories_menu(self):
        """Opção 10: Listar Diretórios e Estrutura"""
        print("\n📁 LISTAR DIRETÓRIOS E ESTRUTURA\n")
        directory = input("Diretório inicial (padrão: ./): ").strip() or "./"
        directory = utils.normalize_path(directory)
        if not utils.is_valid_directory(directory):
            print(f"❌ Diretório inválido: {directory}")
            input("Pressione ENTER para continuar...")
            return

        depth_str = input("Profundidade máxima (deixe em branco para ilimitado): ").strip()
        max_depth = int(depth_str) if depth_str.isdigit() else None

        print("\nVisualização:")
        print("1. 🌳 Árvore de diretórios")
        print("2. 📋 Tabela com estatísticas")
        view_choice = input("Escolha (1-2, padrão: 1): ").strip() or '1'

        searcher = AdvancedFileSearch(max_depth=max_depth)

        if view_choice == '1':
            searcher.print_directory_tree(directory, max_depth=max_depth)
        else:
            dirs = searcher.list_directories(directory, recursive=True, max_depth=max_depth)
            if not dirs:
                print("\n⚠️  Nenhum subdiretório encontrado.")
            else:
                print(f"\n{'='*80}")
                print(f"  Diretórios em '{directory}'  ({len(dirs)} encontrados)")
                print(f"{'='*80}")
                print(f"{'#':<4} {'Nome':<30} {'Arquivos':>8}  {'Tamanho':>10}  Profundidade")
                print(f"{'-'*4} {'-'*30} {'-'*8}  {'-'*10}  {'-'*12}")
                for idx, d in enumerate(dirs, 1):
                    name = d['name'][:28]
                    print(
                        f"{idx:<4} {name:<30} {d['file_count']:>8}  "
                        f"{d['total_size']:>10}  {d['depth']}"
                    )
                print(f"{'='*80}")

        input("\nPressione ENTER para continuar...")

    def list_packages_menu(self):
        """Opção 11: Listar e Escanear Pacotes"""
        print("\n📦 LISTAR E ESCANEAR PACOTES\n")
        print("1. 📋 Listar pacotes compactados")
        print("2. 🔍 Buscar padrão dentro de pacotes")
        print("3. 🛡️  Escanear arquivos dentro de pacotes")

        choice = input("\nEscolha (1-3): ").strip()
        directory = input("Diretório de busca (padrão: ./): ").strip() or "./"
        directory = utils.normalize_path(directory)
        if not utils.is_valid_directory(directory):
            print(f"❌ Diretório inválido: {directory}")
            input("Pressione ENTER para continuar...")
            return

        recursive = input("Recursivo? (s/n, padrão: s): ").lower() != 'n'
        searcher = AdvancedFileSearch()

        if choice == '1':
            packages = searcher.list_packages(directory, recursive)
            if not packages:
                print("\n⚠️  Nenhum pacote encontrado.")
            else:
                print(f"\n{'='*80}")
                print(f"  Pacotes encontrados: {len(packages)}")
                print(f"{'='*80}")
                for idx, pkg in enumerate(packages, 1):
                    n_entries = len(pkg.get('contents', []))
                    print(
                        f"{idx}. [{pkg.get('package_type','?').upper()}] {pkg['name']}  "
                        f"({pkg['size']}, {n_entries} entradas)"
                    )
                    print(f"   └─ {pkg['path']}")
                print(f"{'='*80}")

        elif choice == '2':
            pattern = input("Padrão de busca (ex: *.exe, malware*): ").strip()
            results = searcher.search_in_packages(pattern, directory, recursive)
            if not results:
                print("\n⚠️  Nenhuma entrada encontrada nos pacotes.")
            else:
                print(f"\n{'='*80}")
                print(f"  Entradas correspondentes: {len(results)}")
                print(f"{'='*80}")
                for idx, r in enumerate(results, 1):
                    print(
                        f"{idx}. {r['entry_name']}  ({r['entry_size']})"
                    )
                    print(f"   └─ Pacote: {r['package_path']}")
                print(f"{'='*80}")

        elif choice == '3':
            print("\n🛡️  Escaneando pacotes (análise de nomes e metadados)...")
            packages = searcher.list_packages(directory, recursive)
            threats_found = 0
            from scanner import check_extension
            for pkg in packages:
                for entry_name, _entry_size in pkg.get('contents', []):
                    if check_extension(entry_name):
                        print(
                            f"⚠️  Extensão suspeita em pacote: '{entry_name}' "
                            f"dentro de {pkg['name']}"
                        )
                        threats_found += 1
            print(f"\n✓ {len(packages)} pacote(s) analisados, {threats_found} entrada(s) suspeita(s)")

        else:
            print("❌ Opção inválida")

        input("\nPressione ENTER para continuar...")

    def custom_scan(self):
        """Opção 12: Scan Customizado com múltiplos critérios"""
        print("\n🎯 SCAN CUSTOMIZADO\n")
        print("Configure os critérios de busca (deixe em branco para ignorar o critério):\n")

        directory = input("Diretório de busca (padrão: ./): ").strip() or "./"
        directory = utils.normalize_path(directory)
        if not utils.is_valid_directory(directory):
            print(f"❌ Diretório inválido: {directory}")
            input("Pressione ENTER para continuar...")
            return

        recursive = input("Recursivo? (s/n, padrão: s): ").lower() != 'n'

        # Coletar critérios
        criteria = {}

        raw_exts = input("Extensões (ex: .exe,.dll — ou deixe em branco): ").strip()
        if raw_exts:
            criteria['extensions'] = [e.strip() for e in raw_exts.split(',')]

        raw_pattern = input("Padrão glob/regex (ex: malware*, /^ransom.*/): ").strip()
        if raw_pattern:
            criteria['pattern'] = raw_pattern

        min_mb = input("Tamanho mínimo em MB (ou deixe em branco): ").strip()
        if min_mb:
            try:
                criteria['min_size'] = int(float(min_mb) * 1024 * 1024)
            except ValueError:
                pass

        max_mb = input("Tamanho máximo em MB (ou deixe em branco): ").strip()
        if max_mb:
            try:
                criteria['max_size'] = int(float(max_mb) * 1024 * 1024)
            except ValueError:
                pass

        start_date = input("Data inicial YYYY-MM-DD (ou deixe em branco): ").strip() or None
        if start_date:
            criteria['start_date'] = start_date

        end_date = input("Data final YYYY-MM-DD (ou deixe em branco): ").strip() or None
        if end_date:
            criteria['end_date'] = end_date

        # Validar
        errors = utils.validate_search_criteria(criteria)
        if errors:
            print("\n❌ Critérios inválidos:")
            for err in errors:
                print(f"  • {err}")
            input("Pressione ENTER para continuar...")
            return

        if not criteria:
            print("⚠️  Nenhum critério definido. O scan usará todos os arquivos do diretório.")

        # Executar scan customizado
        self.threats = self.scanner.scan_with_advanced_search(criteria, directory, recursive)
        if self.threats:
            self.scanner.generate_report('custom_scan_report.json')

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
            elif choice == '9':
                self.advanced_file_search()
            elif choice == '10':
                self.list_directories_menu()
            elif choice == '11':
                self.list_packages_menu()
            elif choice == '12':
                self.custom_scan()
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
