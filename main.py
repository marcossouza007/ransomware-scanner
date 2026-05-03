# ============================================================================
# RANSOMWARE SCANNER & RECOVERY TOOL v2.0 - MAIN
# ============================================================================

import os
import sys
from datetime import datetime
from pathlib import Path

import config
import utils
from scanner import RansomwareScanner
from quarantine import QuarantineManager, SecureDeleter
from decryptor import RansomwareDecryptor
from pdf_report import PDFReportGenerator
from virustotal_checker import check_file_virustotal, check_hash_virustotal
from cve_checker import search_cves, search_cves_by_ransomware
from advanced_file_search import advanced_search, find_by_extension
from virus_detector import get_detector as get_virus_detector

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
        print("8. 🔎 Busca Avançada de Arquivos")
        print("9. 🌐 Verificar Hash no VirusTotal")
        print("10. 📊 Buscar CVEs Relacionadas")
        print("11. 🦠 Detecção de Vírus Básica")
        print("12. ✖️  Sair")
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
        print(f"\n🌐 VirusTotal API Key: {'✅ Configurada' if config.VIRUSTOTAL_CONFIG.get('api_key') else '❌ Não configurada'}")
        
        input("\nPressione ENTER para continuar...")

    # -----------------------------------------------------------------------
    # OPÇÃO 8 – BUSCA AVANÇADA DE ARQUIVOS
    # -----------------------------------------------------------------------

    def advanced_file_search(self):
        """Opção 8: Busca Avançada de Arquivos"""
        print("\n🔎 BUSCA AVANÇADA DE ARQUIVOS\n")
        print("Exemplos de padrões: *.exe  *.encrypted  ransom*  **/malware*")
        print()

        pattern = input("Padrão de busca (ex: *.exe): ").strip()
        if not pattern:
            print("❌ Padrão não pode ser vazio")
            input("Pressione ENTER para continuar...")
            return

        directories_input = input(
            "Diretório(s) para buscar (separados por vírgula, padrão: ./): "
        ).strip() or "./"
        directories = [d.strip() for d in directories_input.split(',') if d.strip()]

        recursive = input("Busca recursiva? (s/n, padrão: s): ").lower() != 'n'

        # Filtros opcionais
        print("\n[Filtros opcionais – pressione ENTER para ignorar]")
        min_size_str = input("Tamanho mínimo em bytes: ").strip()
        max_size_str = input("Tamanho máximo em bytes: ").strip()
        start_date_str = input("Data início modificação (YYYY-MM-DD): ").strip()
        end_date_str = input("Data fim modificação (YYYY-MM-DD): ").strip()

        min_size = int(min_size_str) if min_size_str.isdigit() else None
        max_size = int(max_size_str) if max_size_str.isdigit() else None

        print(f"\n🔎 Buscando '{pattern}' em: {', '.join(directories)}...")

        results = advanced_search(
            query=pattern,
            directories=directories,
            recursive=recursive,
            min_size=min_size,
            max_size=max_size,
            start_date=start_date_str or None,
            end_date=end_date_str or None,
        )

        print(f"\n✅ Encontrados: {len(results)} arquivo(s)\n")

        for idx, entry in enumerate(results[:50], 1):
            size_str = utils.format_size(entry['size'])
            print(f"{idx:3}. {entry['path']}")
            print(f"      └─ {size_str}  |  Modificado: {entry['modified'][:10]}")

        if len(results) > 50:
            print(f"\n... e mais {len(results) - 50} arquivo(s) não exibidos.")

        if results:
            add_to_scan = input(
                "\nDeseja adicionar esses arquivos como ameaças suspeitas? (s/n): "
            ).lower()
            if add_to_scan == 's':
                for entry in results:
                    if not any(t['path'] == entry['path'] for t in self.threats):
                        self.threats.append({
                            'path': entry['path'],
                            'risk_score': 0.0,
                            'size': entry['size'],
                            'timestamp': datetime.now().isoformat(),
                            'file_hash': utils.calculate_sha256(entry['path']) or 'N/A',
                            'threat_type': 'search_result',
                            'extension': entry['extension'],
                        })
                print(f"✅ {len(results)} arquivo(s) adicionados como suspeitos")

        input("\nPressione ENTER para continuar...")

    # -----------------------------------------------------------------------
    # OPÇÃO 9 – VIRUSTOTAL LOOKUP
    # -----------------------------------------------------------------------

    def virustotal_lookup(self):
        """Opção 9: Verificar Hash no VirusTotal"""
        print("\n🌐 VERIFICAR HASH NO VIRUSTOTAL\n")

        if not config.VIRUSTOTAL_CONFIG.get('api_key'):
            print("⚠️  API key do VirusTotal não configurada.")
            print("   Configure a variável de ambiente VIRUSTOTAL_API_KEY ou")
            print("   edite VIRUSTOTAL_CONFIG['api_key'] em config.py")
            print()

        print("1. Verificar por hash SHA256")
        print("2. Verificar arquivo (calcula hash automaticamente)")
        print("3. Verificar ameaças detectadas no último scan")
        print()

        choice = input("Escolha (1/2/3): ").strip()

        if choice == '1':
            sha256 = input("\nDigite o hash SHA256: ").strip()
            if len(sha256) != 64:
                print("❌ Hash SHA256 inválido (deve ter 64 caracteres)")
                input("Pressione ENTER para continuar...")
                return
            print(f"\n🔄 Consultando VirusTotal para hash {sha256[:16]}...")
            result = check_hash_virustotal(sha256)
            self._display_virustotal_result(result, sha256[:16] + '...')

        elif choice == '2':
            filepath = input("\nDigite o caminho do arquivo: ").strip()
            if not utils.is_valid_file(filepath):
                print(f"❌ Arquivo inválido: {filepath}")
                input("Pressione ENTER para continuar...")
                return
            print(f"\n🔄 Consultando VirusTotal para: {filepath}")
            result = check_file_virustotal(filepath)
            self._display_virustotal_result(result, filepath)

        elif choice == '3':
            if not self.threats:
                print("❌ Nenhuma ameaça detectada. Execute um scan primeiro.")
                input("Pressione ENTER para continuar...")
                return
            print(f"\n🔄 Verificando {len(self.threats)} ameaça(s)...\n")
            for threat in self.threats[:10]:
                sha256 = threat.get('file_hash', '')
                if sha256:
                    result = check_hash_virustotal(sha256)
                    print(f"\n📄 {threat['path'][:60]}")
                    self._display_virustotal_result(result, sha256[:16] + '...')
        else:
            print("❌ Opção inválida")

        input("\nPressione ENTER para continuar...")

    def _display_virustotal_result(self, result: dict, label: str):
        """Exibe resultado do VirusTotal de forma formatada"""
        if result.get('offline'):
            # Display API status message (not sensitive data)
            status_msg = str(result.get('message', 'Modo offline'))
            print(f"   ⚠️  {status_msg}")
            return

        detected = result.get('detected', False)
        score = int(result.get('score', 0))
        engines_det = int(result.get('engines_detected', 0))
        engines_tot = int(result.get('engines_total', 0))
        # malware_names contains AV engine detection labels (e.g. "Trojan.Generic")
        detection_labels = [str(n) for n in result.get('malware_names', [])]
        cached = result.get('from_cache', False)

        icon = '🔴' if detected else '🟢'
        cache_tag = ' [cache]' if cached else ''

        print(f"   {icon} {label}{cache_tag}")
        print(f"   ├─ Detectado: {'SIM' if detected else 'NÃO'}")
        print(f"   ├─ Score: {score}/100  ({engines_det}/{engines_tot} engines)")
        if detection_labels:
            print(f"   └─ Nomes: {', '.join(detection_labels[:5])}")
        permalink = str(result.get('permalink', ''))
        if permalink:
            print(f"   └─ Link: {permalink}")

    # -----------------------------------------------------------------------
    # OPÇÃO 10 – BUSCAR CVEs
    # -----------------------------------------------------------------------

    def search_cves_menu(self):
        """Opção 10: Buscar CVEs Relacionadas"""
        print("\n📊 BUSCAR CVEs RELACIONADAS\n")
        print("Busca no NVD (National Vulnerability Database) por CVEs")
        print("relacionadas a ransomware, extensões de arquivo ou malware.")
        print()

        keyword = input("Termo de busca (ex: wannacry, .encrypted, lockbit): ").strip()
        if not keyword:
            print("❌ Termo não pode ser vazio")
            input("Pressione ENTER para continuar...")
            return

        severity_options = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', '']
        print("\nFiltro de severidade mínima:")
        print("1. CRITICAL  2. HIGH  3. MEDIUM  4. LOW  5. Todos")
        sev_choice = input("Escolha (1-5, padrão: 5): ").strip()
        severity_map = {'1': 'CRITICAL', '2': 'HIGH', '3': 'MEDIUM', '4': 'LOW', '5': None}
        severity = severity_map.get(sev_choice)

        print(f"\n🔄 Buscando CVEs para '{keyword}'...")
        result = search_cves(keyword, severity_filter=severity)

        if result.get('offline'):
            print(f"⚠️  {result.get('message', 'Sem conexão com NVD')}")
            input("\nPressione ENTER para continuar...")
            return

        cves = result.get('cves', [])
        print(f"\n✅ Encontradas: {result.get('total_found', 0)} CVE(s)")
        print(f"   Score CVSS máximo: {result.get('cvss_score', 0):.1f}")
        print(f"   Severidade: {result.get('severity', 'N/A')}")
        if result.get('from_cache'):
            print("   [resultado do cache]")

        print()
        for idx, cve in enumerate(cves[:10], 1):
            severity_icon = {
                'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡',
                'LOW': '🟢', 'NONE': '⚪'
            }.get(cve.get('severity', 'NONE'), '⚪')
            print(f"{idx:2}. {severity_icon} {cve['id']}  (CVSS {cve['cvss_score']:.1f})")
            print(f"    {cve['description'][:120]}")
            print()

        if len(cves) > 10:
            print(f"... e mais {len(cves) - 10} CVE(s) não exibidas.")

        recs = result.get('recommendations', [])
        if recs:
            print("\n💡 Recomendações:")
            for rec in recs:
                print(f"  • {rec}")

        input("\nPressione ENTER para continuar...")

    # -----------------------------------------------------------------------
    # OPÇÃO 11 – DETECÇÃO DE VÍRUS BÁSICA
    # -----------------------------------------------------------------------

    def virus_detection_menu(self):
        """Opção 11: Detecção de Vírus Básica"""
        print("\n🦠 DETECÇÃO DE VÍRUS BÁSICA\n")
        print("1. Analisar arquivo específico")
        print("2. Analisar ameaças do último scan")
        print("3. Analisar diretório")
        print()

        choice = input("Escolha (1/2/3): ").strip()
        detector = get_virus_detector()

        if choice == '1':
            filepath = input("\nDigite o caminho do arquivo: ").strip()
            if not utils.is_valid_file(filepath):
                print(f"❌ Arquivo inválido: {filepath}")
                input("Pressione ENTER para continuar...")
                return
            print(f"\n🔄 Analisando: {filepath}")
            prob = detector.detect_virus_probability(filepath)
            names = detector.get_virus_names()
            self._display_virus_result(filepath, prob, names)

        elif choice == '2':
            if not self.threats:
                print("❌ Nenhuma ameaça detectada. Execute um scan primeiro.")
                input("Pressione ENTER para continuar...")
                return
            print(f"\n🔄 Analisando {len(self.threats)} ameaça(s)...\n")
            for threat in self.threats:
                filepath = threat['path']
                if not utils.is_valid_file(filepath):
                    continue
                prob = detector.detect_virus_probability(filepath)
                names = detector.get_virus_names()
                self._display_virus_result(filepath, prob, names)

        elif choice == '3':
            directory = input("\nDigite o caminho do diretório: ").strip() or "./"
            if not utils.validate_directory(directory):
                print(f"❌ Diretório inválido: {directory}")
                input("Pressione ENTER para continuar...")
                return
            files = list(Path(directory).rglob('*'))
            files = [f for f in files if f.is_file()]
            print(f"\n🔄 Analisando {len(files)} arquivo(s)...\n")
            suspicious = []
            for fpath in files[:200]:  # Limitar a 200 arquivos
                prob = detector.detect_virus_probability(str(fpath))
                if prob > 0.3:
                    names = detector.get_virus_names()
                    suspicious.append((str(fpath), prob, names))

            print(f"\n🦠 Arquivos suspeitos: {len(suspicious)}")
            for fp, prob, names in suspicious:
                self._display_virus_result(fp, prob, names)
        else:
            print("❌ Opção inválida")

        input("\nPressione ENTER para continuar...")

    def _display_virus_result(self, filepath: str, probability: float, names: list):
        """Exibe resultado da detecção de vírus"""
        if probability > 0.75:
            icon = "🔴 CRÍTICO"
        elif probability > 0.45:
            icon = "🟠 ALTO"
        elif probability > 0.25:
            icon = "🟡 MÉDIO"
        elif probability > 0:
            icon = "🟢 BAIXO"
        else:
            icon = "✅ LIMPO"

        print(f"  📄 {filepath[:70]}")
        print(f"     ├─ Probabilidade: {probability:.1%} ({icon})")
        if names:
            print(f"     └─ Detectado: {', '.join(names[:3])}")
        print()

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
                self.advanced_file_search()
            elif choice == '9':
                self.virustotal_lookup()
            elif choice == '10':
                self.search_cves_menu()
            elif choice == '11':
                self.virus_detection_menu()
            elif choice == '12':
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
