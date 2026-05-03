#!/usr/bin/env python3
# ============================================================================
# INTERFACE CLI INTERATIVA - RANSOMWARE SCANNER v2.0
# ============================================================================

import os
import sys
from datetime import datetime
from typing import Optional

from config import (
    SCAN_CONFIG, DEFAULT_OVERWRITE_METHOD, SecureOverwriteMethod,
    OVERWRITE_PASSES, QUARANTINE_DIR, REPORTS_DIR,
)
from utils import (
    logger, print_header, print_section, print_success,
    print_error, print_warning, print_info,
    get_user_confirmation, format_bytes, format_timestamp,
    save_json_report,
)
from scanner import RansomwareScanner
from quarantine import QuarantineManager, SecureDeleter
from decryptor import RansomwareDecryptor
from pdf_report import PDFReportGenerator

# ============================================================================
# ESTADO GLOBAL DA SESSÃO
# ============================================================================

class AppState:
    """Mantém estado global da aplicação entre menus"""

    def __init__(self):
        self.scanner = RansomwareScanner(
            threat_threshold=SCAN_CONFIG['threat_threshold']
        )
        self.quarantine_manager = QuarantineManager()
        self.decryptor = RansomwareDecryptor()
        self.pdf_generator = PDFReportGenerator()
        self.secure_deleter = SecureDeleter(method=DEFAULT_OVERWRITE_METHOD)

        # Configurações mutáveis em runtime
        self.threat_threshold: float = SCAN_CONFIG['threat_threshold']
        self.recursive_scan: bool = SCAN_CONFIG['recursive']
        self.overwrite_method: SecureOverwriteMethod = DEFAULT_OVERWRITE_METHOD
        self.last_scan_dir: Optional[str] = None

    def update_settings(
        self,
        threat_threshold: float = None,
        recursive_scan: bool = None,
        overwrite_method: SecureOverwriteMethod = None,
    ):
        """Atualiza configurações e recria os objetos necessários"""
        if threat_threshold is not None:
            self.threat_threshold = threat_threshold
            self.scanner.threat_threshold = threat_threshold

        if recursive_scan is not None:
            self.recursive_scan = recursive_scan

        if overwrite_method is not None:
            self.overwrite_method = overwrite_method
            self.secure_deleter = SecureDeleter(method=overwrite_method)


# ============================================================================
# FUNÇÕES DE SUPORTE AO MENU
# ============================================================================

def _clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def _pause():
    input("\n[Pressione Enter para continuar...]")


def _prompt(text: str, default: str = '') -> str:
    """Lê entrada do usuário com suporte a valor padrão"""
    if default:
        raw = input(f"{text} [{default}]: ").strip()
        return raw if raw else default
    return input(f"{text}: ").strip()


def _choose_from_list(title: str, items: list, display_fn=None) -> Optional[int]:
    """Exibe lista numerada e retorna índice escolhido (0-based) ou None"""
    if not items:
        print_warning("Lista vazia.")
        return None

    print(f"\n{title}")
    print("-" * 60)
    for idx, item in enumerate(items, 1):
        label = display_fn(item) if display_fn else str(item)
        print(f"  {idx:3}. {label}")
    print("    0. Voltar")

    while True:
        raw = input("\nEscolha: ").strip()
        if raw == '0':
            return None
        try:
            choice = int(raw)
            if 1 <= choice <= len(items):
                return choice - 1
        except ValueError:
            pass
        print_warning("Opção inválida.")


# ============================================================================
# MENU 1 — ESCANEAR DIRETÓRIO
# ============================================================================

def menu_scan(state: AppState):
    print_header("🔍 ESCANEAR DIRETÓRIO")

    default_dir = state.last_scan_dir or os.getcwd()
    directory = _prompt("Diretório para escanear", default_dir)

    if not os.path.isdir(directory):
        print_error(f"Diretório não encontrado: {directory}")
        _pause()
        return

    state.last_scan_dir = directory

    print_info(f"Threshold de risco: {state.threat_threshold:.0%}")
    print_info(f"Scan recursivo: {'Sim' if state.recursive_scan else 'Não'}")
    print()

    threats = state.scanner.scan_directory(directory, recursive=state.recursive_scan)

    if threats:
        print()
        if get_user_confirmation("Deseja colocar as ameaças em quarentena agora?"):
            _quarantine_threats(state, threats)

        if get_user_confirmation("Deseja salvar relatório JSON?"):
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            state.scanner.generate_report(f"scan_report_{ts}.json")

    _pause()


def _quarantine_threats(state: AppState, threats: list):
    """Coloca lista de ameaças em quarentena"""
    print_section("Colocando ameaças em quarentena...")
    for threat in threats:
        state.quarantine_manager.quarantine_file(
            file_path=threat['path'],
            risk_score=threat['risk_score'],
            threat_type=threat.get('threat_type', 'unknown'),
            reason=f"Score de risco: {threat['risk_score']:.2%}",
        )


# ============================================================================
# MENU 2 — VER AMEAÇAS DETECTADAS
# ============================================================================

def menu_view_threats(state: AppState):
    print_header("📋 AMEAÇAS DETECTADAS")

    threats = state.scanner.infected_files

    if not threats:
        print_info("Nenhuma ameaça detectada na sessão atual.")
        print_info("Execute um scan primeiro (opção 1).")
        _pause()
        return

    print(f"\nTotal de ameaças: {len(threats)}\n")
    print(f"{'#':<4} {'Arquivo':<35} {'Tipo':<15} {'Risco':<10} {'Score':<8} {'Hash SHA256':<20}")
    print("-" * 100)

    for idx, threat in enumerate(threats, 1):
        filename = os.path.basename(threat['path'])[:33]
        ttype = threat.get('threat_type', 'unknown')[:13]
        score = threat.get('risk_score', 0)
        risk_label = _risk_label(score)
        sha = (threat.get('file_hash') or 'N/A')[:18]
        print(f"{idx:<4} {filename:<35} {ttype:<15} {risk_label:<10} {score:<8.2%} {sha}")

    print()
    print_info(f"Diretório escaneado: {state.last_scan_dir or 'N/A'}")

    _pause()


def _risk_label(score: float) -> str:
    if score > 0.75:
        return '🔴 CRÍTICO'
    elif score > 0.45:
        return '🟠 ALTO'
    elif score > 0.25:
        return '🟡 MÉDIO'
    return '🟢 BAIXO'


# ============================================================================
# MENU 3 — TENTAR RECUPERAÇÃO
# ============================================================================

def menu_recovery(state: AppState):
    print_header("🔐 TENTAR RECUPERAÇÃO")

    threats = state.scanner.infected_files
    quarantined = state.quarantine_manager.list_quarantined()

    # Combina ameaças da sessão com arquivos em quarentena
    candidates = list(threats)
    for q in quarantined:
        qpath = q.get('quarantine_path', '')
        if qpath and os.path.isfile(qpath):
            if not any(t['path'] == qpath for t in candidates):
                candidates.append({
                    'path': qpath,
                    'risk_score': q.get('risk_score', 0),
                    'threat_type': q.get('threat_type', 'unknown'),
                })

    if not candidates:
        print_info("Nenhum arquivo disponível para recuperação.")
        print_info("Execute um scan ou verifique a quarentena.")
        _pause()
        return

    print("\nOpções de recuperação:")
    print("  1. Tentar todos os tipos de ransomware conhecidos (arquivo específico)")
    print("  2. Tentar chave específica (arquivo específico)")
    print("  3. Recuperar de backup")
    print("  0. Voltar")

    choice = _prompt("\nEscolha uma opção")

    if choice == '0':
        return

    if choice in ('1', '2'):
        idx = _choose_from_list(
            "Selecione o arquivo",
            candidates,
            display_fn=lambda t: f"{os.path.basename(t['path'])} [{_risk_label(t['risk_score'])}]",
        )
        if idx is None:
            return

        target = candidates[idx]['path']

        if choice == '1':
            success = state.decryptor.attempt_all_keys(target)
        else:
            print("\nChaves disponíveis:")
            from config import KNOWN_RANSOMWARE_KEYS
            for k in KNOWN_RANSOMWARE_KEYS:
                print(f"  - {k}")
            key_name = _prompt("Nome da chave").lower()
            success = state.decryptor.attempt_known_decryption(target, key_name)

        if success:
            print_success("Descriptografia concluída com sucesso!")
        else:
            print_warning("Não foi possível recuperar o arquivo com as chaves disponíveis.")

    elif choice == '3':
        target = _prompt("Caminho do arquivo infectado")
        backup = _prompt("Caminho do arquivo de backup")
        state.decryptor.recover_from_backup(target, backup)
    else:
        print_warning("Opção inválida.")

    if get_user_confirmation("Salvar relatório de recuperação?"):
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        state.decryptor.generate_recovery_report(f"recovery_report_{ts}.json")

    _pause()


# ============================================================================
# MENU 4 — GERENCIAR QUARENTENA
# ============================================================================

def menu_quarantine(state: AppState):
    while True:
        print_header("🔒 GERENCIAR QUARENTENA")

        quarantined = state.quarantine_manager.list_quarantined()

        print(f"Arquivos em quarentena: {len(quarantined)}")
        print()
        print("  1. Listar arquivos em quarentena")
        print("  2. Restaurar arquivo")
        print("  3. Deletar seguro de arquivo em quarentena")
        print("  4. Salvar relatório JSON de quarentena")
        print("  0. Voltar")

        choice = _prompt("\nEscolha")

        if choice == '0':
            break

        elif choice == '1':
            _list_quarantine(quarantined)

        elif choice == '2':
            _restore_from_quarantine(state, quarantined)

        elif choice == '3':
            _secure_delete_quarantine(state, quarantined)

        elif choice == '4':
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            state.quarantine_manager.generate_quarantine_report(
                f"quarantine_report_{ts}.json"
            )
            _pause()

        else:
            print_warning("Opção inválida.")


def _list_quarantine(quarantined: list):
    if not quarantined:
        print_info("Nenhum arquivo em quarentena.")
        _pause()
        return

    print(f"\n{'#':<4} {'Arquivo':<35} {'Tipo':<15} {'Risco':<10} {'Score':<8} {'Data':<12}")
    print("-" * 90)

    for idx, item in enumerate(quarantined, 1):
        filename = os.path.basename(item.get('original_path', 'N/A'))[:33]
        ttype = item.get('threat_type', 'unknown')[:13]
        score = item.get('risk_score', 0)
        risk_label = _risk_label(score)
        date = item.get('quarantined_at', 'N/A')[:10]
        print(f"{idx:<4} {filename:<35} {ttype:<15} {risk_label:<10} {score:<8.2%} {date}")

    _pause()


def _restore_from_quarantine(state: AppState, quarantined: list):
    idx = _choose_from_list(
        "Selecione arquivo para restaurar",
        quarantined,
        display_fn=lambda q: (
            f"{os.path.basename(q.get('original_path', 'N/A'))} "
            f"[{_risk_label(q.get('risk_score', 0))}]"
        ),
    )
    if idx is None:
        return

    item = quarantined[idx]
    default_restore = item.get('original_path', '')
    restore_path = _prompt("Caminho para restaurar", default_restore)

    if get_user_confirmation(
        f"Restaurar '{os.path.basename(item.get('original_path', ''))}' para '{restore_path}'?"
    ):
        state.quarantine_manager.restore_file(
            item['quarantine_id'], restore_path
        )
    _pause()


def _secure_delete_quarantine(state: AppState, quarantined: list):
    idx = _choose_from_list(
        "Selecione arquivo para deletar permanentemente",
        quarantined,
        display_fn=lambda q: (
            f"{os.path.basename(q.get('original_path', 'N/A'))} "
            f"[{_risk_label(q.get('risk_score', 0))}]"
        ),
    )
    if idx is None:
        return

    item = quarantined[idx]
    qpath = item.get('quarantine_path', '')

    if not qpath or not os.path.isfile(qpath):
        print_error("Arquivo em quarentena não encontrado.")
        _pause()
        return

    print_warning(f"ATENÇÃO: O arquivo será deletado PERMANENTEMENTE com {state.overwrite_method.value}!")
    if get_user_confirmation("Confirma a exclusão permanente?"):
        state.secure_deleter.secure_delete(qpath)
    _pause()


# ============================================================================
# MENU 5 — GERAR RELATÓRIOS PDF
# ============================================================================

def menu_pdf_reports(state: AppState):
    print_header("📄 GERAR RELATÓRIOS PDF")

    print("\n  1. Relatório de Scan")
    print("  2. Relatório de Quarentena")
    print("  3. Relatório de Recuperação")
    print("  0. Voltar")

    choice = _prompt("\nEscolha")

    if choice == '0':
        return

    elif choice == '1':
        threats = state.scanner.infected_files
        if not threats:
            print_warning("Nenhuma ameaça detectada. Execute um scan primeiro.")
            _pause()
            return

        by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        by_type: dict = {}
        for t in threats:
            score = t.get('risk_score', 0)
            if score > 0.75:
                by_risk['critical'] += 1
            elif score > 0.45:
                by_risk['high'] += 1
            elif score > 0.25:
                by_risk['medium'] += 1
            else:
                by_risk['low'] += 1
            ttype = t.get('threat_type', 'unknown')
            by_type[ttype] = by_type.get(ttype, 0) + 1

        scan_data = {
            'timestamp': datetime.now().isoformat(),
            'total_threats': len(threats),
            'scan_duration': (
                (state.scanner.end_time - state.scanner.start_time).total_seconds()
                if state.scanner.start_time and state.scanner.end_time else 0
            ),
            'by_risk': by_risk,
            'by_threat_type': by_type,
            'threats': threats,
        }

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        state.pdf_generator.generate_scan_report(scan_data, f"scan_report_{ts}.pdf")

    elif choice == '2':
        report = state.quarantine_manager.generate_quarantine_report()
        state.pdf_generator.generate_quarantine_report(report)

    elif choice == '3':
        recovery_data = {
            'timestamp': datetime.now().isoformat(),
            'total_recovered': len(state.decryptor.decrypted_files),
            'recovered_files': state.decryptor.decrypted_files,
        }
        state.pdf_generator.generate_recovery_report(recovery_data)

    else:
        print_warning("Opção inválida.")

    _pause()


# ============================================================================
# MENU 6 — VER ESTATÍSTICAS
# ============================================================================

def menu_statistics(state: AppState):
    print_header("📊 ESTATÍSTICAS DA SESSÃO")

    stats = state.scanner.get_statistics()
    quarantined = state.quarantine_manager.list_quarantined()

    print_section("Scanner")
    if stats['total'] == 0:
        print_info("Nenhum scan realizado ainda.")
    else:
        print(f"  Total de ameaças detectadas : {stats['total']}")
        print(f"  Tamanho total               : {stats.get('total_size', 'N/A')}")
        by_risk = stats.get('by_risk', {})
        print(f"  Críticas 🔴                 : {by_risk.get('critical', 0)}")
        print(f"  Altas 🟠                    : {by_risk.get('high', 0)}")
        print(f"  Médias 🟡                   : {by_risk.get('medium', 0)}")
        print(f"  Baixas 🟢                   : {by_risk.get('low', 0)}")

    print_section("Quarentena")
    print(f"  Arquivos em quarentena      : {len(quarantined)}")

    print_section("Recuperação")
    print(f"  Arquivos recuperados        : {len(state.decryptor.decrypted_files)}")

    print_section("Configurações Ativas")
    print(f"  Threshold de risco          : {state.threat_threshold:.0%}")
    print(f"  Scan recursivo              : {'Sim' if state.recursive_scan else 'Não'}")
    print(f"  Método de sobrescrita       : {state.overwrite_method.value}")
    print(f"  Último diretório escaneado  : {state.last_scan_dir or 'N/A'}")
    print(f"  Diretório de quarentena     : {QUARANTINE_DIR}")
    print(f"  Diretório de relatórios     : {REPORTS_DIR}")

    _pause()


# ============================================================================
# MENU 7 — CONFIGURAÇÕES
# ============================================================================

def menu_settings(state: AppState):
    while True:
        print_header("⚙️  CONFIGURAÇÕES")

        print(f"\n  1. Threshold de detecção     [{state.threat_threshold:.0%}]")
        print(f"  2. Scan recursivo            [{'Sim' if state.recursive_scan else 'Não'}]")
        print(f"  3. Método de sobrescrita     [{state.overwrite_method.value}]")
        print("  0. Voltar")

        choice = _prompt("\nEscolha")

        if choice == '0':
            break

        elif choice == '1':
            raw = _prompt(f"Novo threshold (0-100)", str(int(state.threat_threshold * 100)))
            try:
                val = float(raw) / 100
                if 0.0 <= val <= 1.0:
                    state.update_settings(threat_threshold=val)
                    print_success(f"Threshold atualizado para {val:.0%}")
                else:
                    print_error("Valor deve estar entre 0 e 100.")
            except ValueError:
                print_error("Valor inválido.")

        elif choice == '2':
            state.update_settings(recursive_scan=not state.recursive_scan)
            print_success(f"Scan recursivo: {'Ativado' if state.recursive_scan else 'Desativado'}")

        elif choice == '3':
            print("\nMétodos disponíveis:")
            methods = list(SecureOverwriteMethod)
            for idx, m in enumerate(methods, 1):
                passes = OVERWRITE_PASSES.get(m, '?')
                marker = ' ← atual' if m == state.overwrite_method else ''
                print(f"  {idx}. {m.value} ({passes} passes){marker}")

            raw = _prompt("Número do método", '3')
            try:
                midx = int(raw) - 1
                if 0 <= midx < len(methods):
                    state.update_settings(overwrite_method=methods[midx])
                    print_success(f"Método atualizado: {state.overwrite_method.value}")
                else:
                    print_error("Índice inválido.")
            except ValueError:
                print_error("Valor inválido.")
        else:
            print_warning("Opção inválida.")

        _pause()


# ============================================================================
# MENU PRINCIPAL
# ============================================================================

MENU_OPTIONS = {
    '1': ('🔍 Escanear Diretório', menu_scan),
    '2': ('📋 Ver Ameaças Detectadas', menu_view_threats),
    '3': ('🔐 Tentar Recuperação', menu_recovery),
    '4': ('🔒 Gerenciar Quarentena', menu_quarantine),
    '5': ('📄 Gerar Relatórios PDF', menu_pdf_reports),
    '6': ('📊 Ver Estatísticas', menu_statistics),
    '7': ('⚙️  Configurações', menu_settings),
    '8': ('✖️  Sair', None),
}


def show_main_menu(state: AppState):
    """Exibe menu principal e processa opção escolhida"""
    while True:
        _clear_screen()
        print_header("🛡️  RANSOMWARE SCANNER & RECOVERY TOOL v2.0")

        threats_count = len(state.scanner.infected_files)
        quarantine_count = len(state.quarantine_manager.list_quarantined())

        if threats_count > 0:
            print(f"\n  ⚠️  {threats_count} ameaça(s) detectada(s) na sessão")
        if quarantine_count > 0:
            print(f"  🔒 {quarantine_count} arquivo(s) em quarentena")

        print("\nMenu Principal:\n")
        for key, (label, _) in MENU_OPTIONS.items():
            print(f"  {key}. {label}")

        print()
        choice = _prompt("Escolha uma opção").strip()

        if choice == '8':
            if get_user_confirmation("Deseja sair da aplicação?"):
                print_success("Encerrando aplicação. Até logo! 👋")
                logger.info("Application terminated by user")
                sys.exit(0)
            continue

        if choice in MENU_OPTIONS:
            _, handler = MENU_OPTIONS[choice]
            if handler:
                try:
                    handler(state)
                except KeyboardInterrupt:
                    print("\n\nOperação cancelada pelo usuário.")
                    _pause()
        else:
            print_warning("Opção inválida. Escolha entre 1 e 8.")
            _pause()


# ============================================================================
# PONTO DE ENTRADA
# ============================================================================

def main():
    """Ponto de entrada principal"""
    logger.info("Ransomware Scanner v2.0 started")

    try:
        state = AppState()
        show_main_menu(state)
    except KeyboardInterrupt:
        print("\n\n✖️  Aplicação encerrada pelo usuário.")
        logger.info("Application interrupted by user (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        print_error(f"Erro fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
