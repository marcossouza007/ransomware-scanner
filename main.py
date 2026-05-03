# ============================================================================
# RANSOMWARE SCANNER & RECOVERY TOOL v2.0 - APLICAÇÃO PRINCIPAL (CLI)
# ============================================================================

import os
import sys
from datetime import datetime
from pathlib import Path

from config import (
    SCAN_CONFIG, DEFAULT_OVERWRITE_METHOD, SecureOverwriteMethod,
    QUARANTINE_DIR, REPORTS_DIR, RISK_LEVELS, OVERWRITE_PASSES
)
from utils import (
    logger, print_success, print_error, print_warning, print_info,
    print_header, print_section, get_user_confirmation, format_bytes,
    format_timestamp
)
from scanner import RansomwareScanner
from quarantine import QuarantineManager, SecureDeleter
from decryptor import RansomwareDecryptor
from pdf_report import PDFReportGenerator

# ============================================================================
# ESTADO DA APLICAÇÃO
# ============================================================================

_state = {
    'scanner': None,
    'threats': [],
    'quarantine': None,
    'decryptor': None,
    'pdf': None,
    'threat_threshold': SCAN_CONFIG['threat_threshold'],
    'overwrite_method': DEFAULT_OVERWRITE_METHOD,
}


def _get_scanner() -> RansomwareScanner:
    if _state['scanner'] is None:
        _state['scanner'] = RansomwareScanner(
            threat_threshold=_state['threat_threshold']
        )
    return _state['scanner']


def _get_quarantine() -> QuarantineManager:
    if _state['quarantine'] is None:
        _state['quarantine'] = QuarantineManager()
    return _state['quarantine']


def _get_decryptor() -> RansomwareDecryptor:
    if _state['decryptor'] is None:
        _state['decryptor'] = RansomwareDecryptor()
    return _state['decryptor']


def _get_pdf() -> PDFReportGenerator:
    if _state['pdf'] is None:
        _state['pdf'] = PDFReportGenerator()
    return _state['pdf']


# ============================================================================
# OPÇÕES DO MENU
# ============================================================================

def menu_scan_directory():
    """1. Escanear Diretório"""
    print_header('🔍  ESCANEAR DIRETÓRIO')

    directory = input("\nDigite o caminho do diretório para escanear\n> ").strip()
    if not directory:
        print_error("Caminho não informado.")
        return

    if not os.path.isdir(directory):
        print_error(f"Diretório não encontrado: {directory}")
        return

    recursive_input = input("Scan recursivo? (s/n) [s]: ").strip().lower()
    recursive = recursive_input not in ('n', 'não', 'nao', 'no')

    scanner = _get_scanner()
    scanner.threat_threshold = _state['threat_threshold']

    threats = scanner.scan_directory(directory, recursive=recursive)
    _state['threats'] = threats

    if threats:
        print_warning(f"\n{len(threats)} ameaça(s) detectada(s).")
        if get_user_confirmation("Deseja mover os arquivos para quarentena?"):
            menu_quarantine_all(threats)
    else:
        print_success("Nenhuma ameaça detectada.")

    logger.info(f"Scan realizado em '{directory}': {len(threats)} ameaça(s).")


def menu_view_threats():
    """2. Ver Ameaças Detectadas"""
    print_header('📋  AMEAÇAS DETECTADAS')

    threats = _state['threats']
    if not threats:
        print_info("Nenhuma ameaça carregada. Execute o scan primeiro (opção 1).")
        return

    for idx, threat in enumerate(threats, start=1):
        score = threat.get('risk_score', 0)
        risk_cat = _risk_category(score)
        symbol = RISK_LEVELS.get(risk_cat, {}).get('symbol', '⚪')

        print(f"\n{idx}. {symbol} [{risk_cat.upper()}] {Path(threat['path']).name}")
        print(f"   Caminho : {threat['path']}")
        print(f"   Risco   : {score:.1%}")
        print(f"   Tipo    : {threat.get('threat_type', 'unknown')}")
        print(f"   Extensão: {threat.get('extension', 'N/A')}")
        print(f"   Tamanho : {format_bytes(threat.get('size', 0))}")
        print(f"   SHA256  : {threat.get('file_hash', 'N/A')}")

    stats = _get_scanner().get_statistics()
    print_section(f"\nEstatísticas: {stats['total']} ameaça(s) | {stats.get('total_size', '0 B')}")
    for cat, count in stats.get('by_risk', {}).items():
        symbol = RISK_LEVELS.get(cat, {}).get('symbol', '⚪')
        print(f"  {symbol} {cat.capitalize()}: {count}")


def menu_attempt_recovery():
    """3. Tentar Recuperação"""
    print_header('🔐  TENTAR RECUPERAÇÃO')

    threats = _state['threats']
    if not threats:
        print_info("Nenhuma ameaça carregada. Execute o scan primeiro (opção 1).")
        return

    print("Arquivos disponíveis para recuperação:")
    for idx, t in enumerate(threats, start=1):
        print(f"  {idx}. {Path(t['path']).name}  (risco: {t.get('risk_score', 0):.1%})")

    choice = input("\nEscolha o número do arquivo (ou 'todos'): ").strip()
    decryptor = _get_decryptor()

    if choice.lower() in ('todos', 'all', 't'):
        for t in threats:
            decryptor.attempt_all_keys(t['path'])
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(threats):
                decryptor.attempt_all_keys(threats[idx]['path'])
            else:
                print_error("Número inválido.")
        except ValueError:
            print_error("Entrada inválida.")


def menu_manage_quarantine():
    """4. Gerenciar Quarentena"""
    print_header('🔒  GERENCIAR QUARENTENA')

    qm = _get_quarantine()
    quarantined = qm.list_quarantined()

    if not quarantined:
        print_info("Nenhum arquivo em quarentena.")
        return

    print(f"\n{len(quarantined)} arquivo(s) em quarentena:\n")
    for idx, item in enumerate(quarantined, start=1):
        print(f"{idx}. [{item.get('risk_category', 'N/A').upper()}] "
              f"{Path(item.get('original_path', 'N/A')).name} "
              f"(risco: {item.get('risk_score', 0):.1%})")

    print("\nOpções:")
    print("  r - Restaurar arquivo")
    print("  d - Delete seguro de um arquivo")
    print("  v - Voltar")
    sub = input("\nEscolha: ").strip().lower()

    if sub == 'r':
        _quarantine_restore(quarantined)
    elif sub == 'd':
        _quarantine_secure_delete(quarantined)


def _quarantine_restore(quarantined):
    choice = input("Número do arquivo para restaurar: ").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(quarantined):
            item = quarantined[idx]
            restore_path = input(
                f"Caminho destino [padrão: {item['original_path']}]: "
            ).strip() or item['original_path']
            if get_user_confirmation(f"Restaurar '{Path(item['original_path']).name}' para '{restore_path}'?"):
                _get_quarantine().restore_file(item['quarantine_id'], restore_path)
        else:
            print_error("Número inválido.")
    except ValueError:
        print_error("Entrada inválida.")


def _quarantine_secure_delete(quarantined):
    choice = input("Número do arquivo para deletar: ").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(quarantined):
            item = quarantined[idx]
            if get_user_confirmation(
                f"⚠️  Deletar permanentemente '{Path(item['original_path']).name}'?"
            ):
                deleter = SecureDeleter(method=_state['overwrite_method'])
                deleter.secure_delete(item['quarantine_path'])
        else:
            print_error("Número inválido.")
    except ValueError:
        print_error("Entrada inválida.")


def menu_generate_reports():
    """5. Gerar Relatórios PDF"""
    print_header('📄  GERAR RELATÓRIOS PDF')

    pdf = _get_pdf()

    print("Tipos disponíveis:")
    print("  1. Relatório de Scan")
    print("  2. Relatório de Quarentena")
    print("  3. Relatório de Recuperação")
    print("  4. Todos")
    choice = input("\nEscolha: ").strip()

    if choice in ('1', '4'):
        if _state['threats']:
            scanner = _get_scanner()
            data = {
                'threats': _state['threats'],
                'scan_duration': 0,
                'timestamp': datetime.now().isoformat(),
            }
            path = pdf.generate_scan_report(data)
            if path:
                print_success(f"Scan PDF: {path}")
        else:
            print_warning("Sem dados de scan. Execute o scan primeiro.")

    if choice in ('2', '4'):
        qm = _get_quarantine()
        q_report = qm.generate_quarantine_report()
        path = pdf.generate_quarantine_report(q_report)
        if path:
            print_success(f"Quarentena PDF: {path}")

    if choice in ('3', '4'):
        decryptor = _get_decryptor()
        r_report = decryptor.generate_recovery_report()
        path = pdf.generate_recovery_report(r_report)
        if path:
            print_success(f"Recuperação PDF: {path}")


def menu_view_statistics():
    """6. Ver Estatísticas"""
    print_header('📊  ESTATÍSTICAS')

    threats = _state['threats']
    if not threats:
        print_info("Nenhuma ameaça carregada. Execute o scan primeiro (opção 1).")
        return

    scanner = _get_scanner()
    stats = scanner.get_statistics()

    print(f"\n{'=' * 60}")
    print(f"  Total de Ameaças  : {stats['total']}")
    print(f"  Tamanho Total     : {stats.get('total_size', '0 B')}")
    print(f"{'=' * 60}")

    for cat in ['critical', 'high', 'medium', 'low']:
        count = stats.get('by_risk', {}).get(cat, 0)
        symbol = RISK_LEVELS.get(cat, {}).get('symbol', '⚪')
        bar = '█' * count + '░' * (20 - min(count, 20))
        print(f"  {symbol} {cat.capitalize():<10}: {bar} {count}")

    print(f"{'=' * 60}")

    # Top 5 ameaças mais críticas
    if threats:
        top5 = sorted(threats, key=lambda x: x.get('risk_score', 0), reverse=True)[:5]
        print("\n  Top 5 Ameaças Mais Críticas:")
        for i, t in enumerate(top5, 1):
            print(f"  {i}. {Path(t['path']).name}  —  {t.get('risk_score', 0):.1%}")

    qm = _get_quarantine()
    q_list = qm.list_quarantined()
    print(f"\n  Arquivos em Quarentena: {len(q_list)}")


def menu_settings():
    """7. Configurações"""
    print_header('⚙️  CONFIGURAÇÕES')

    print(f"\n  Threshold atual  : {_state['threat_threshold']:.2f}")
    print(f"  Método de delete : {_state['overwrite_method'].value}")
    print(f"  Dir. Quarentena  : {QUARANTINE_DIR}")
    print(f"  Dir. Relatórios  : {REPORTS_DIR}")

    print("\n  Opções:")
    print("  1. Alterar threshold de detecção")
    print("  2. Alterar método de sobrescrita segura")
    print("  3. Voltar")

    choice = input("\nEscolha: ").strip()

    if choice == '1':
        try:
            val = float(input(f"Novo threshold (0.0-1.0) [{_state['threat_threshold']}]: ").strip())
            if 0.0 <= val <= 1.0:
                _state['threat_threshold'] = val
                # Forçar recriação do scanner com novo threshold
                _state['scanner'] = None
                print_success(f"Threshold atualizado para {val:.2f}")
            else:
                print_error("Valor fora do intervalo (0.0-1.0).")
        except ValueError:
            print_error("Valor inválido.")

    elif choice == '2':
        print("\n  Métodos disponíveis:")
        methods = list(SecureOverwriteMethod)
        for idx, m in enumerate(methods, 1):
            passes = OVERWRITE_PASSES.get(m, '?')
            marker = ' ◄ atual' if m == _state['overwrite_method'] else ''
            print(f"  {idx}. {m.value} ({passes} passes){marker}")
        try:
            sel = int(input("\nEscolha o número: ").strip()) - 1
            if 0 <= sel < len(methods):
                _state['overwrite_method'] = methods[sel]
                print_success(f"Método atualizado para: {methods[sel].value}")
            else:
                print_error("Número inválido.")
        except ValueError:
            print_error("Entrada inválida.")


# ============================================================================
# HELPERS
# ============================================================================

def menu_quarantine_all(threats):
    """Move todas as ameaças detectadas para quarentena"""
    qm = _get_quarantine()
    deleter = SecureDeleter(method=_state['overwrite_method'])

    for threat in threats:
        if not os.path.exists(threat['path']):
            continue
        qm.quarantine_file(
            file_path=threat['path'],
            risk_score=threat.get('risk_score', 0),
            threat_type=threat.get('threat_type', 'unknown'),
            reason='Detectado pelo scanner de ransomware'
        )

    if get_user_confirmation("Aplicar sobrescrita segura nos arquivos originais (se ainda existirem)?"):
        for threat in threats:
            if os.path.exists(threat['path']):
                deleter.secure_delete(threat['path'])


def _risk_category(score: float) -> str:
    if score >= 0.75:
        return 'critical'
    elif score >= 0.45:
        return 'high'
    elif score >= 0.25:
        return 'medium'
    return 'low'


# ============================================================================
# MENU PRINCIPAL
# ============================================================================

MENU_OPTIONS = {
    '1': ('🔍 Escanear Diretório', menu_scan_directory),
    '2': ('📋 Ver Ameaças Detectadas', menu_view_threats),
    '3': ('🔐 Tentar Recuperação', menu_attempt_recovery),
    '4': ('🔒 Gerenciar Quarentena', menu_manage_quarantine),
    '5': ('📄 Gerar Relatórios PDF', menu_generate_reports),
    '6': ('📊 Ver Estatísticas', menu_view_statistics),
    '7': ('⚙️  Configurações', menu_settings),
    '8': ('✖️  Sair', None),
}


def show_main_menu():
    """Exibe menu principal"""
    print_header('🛡️  RANSOMWARE SCANNER & RECOVERY TOOL v2.0')
    print()

    threats_loaded = len(_state['threats'])
    if threats_loaded:
        print(f"  ⚠️  {threats_loaded} ameaça(s) em memória")

    print()
    for key, (label, _) in MENU_OPTIONS.items():
        print(f"  {key}. {label}")
    print()


def main():
    """Ponto de entrada principal"""
    logger.info("Ransomware Scanner started")

    while True:
        try:
            show_main_menu()
            choice = input("Escolha uma opção: ").strip()

            if choice not in MENU_OPTIONS:
                print_warning("Opção inválida. Tente novamente.")
                continue

            label, func = MENU_OPTIONS[choice]

            if func is None:
                # Sair
                if get_user_confirmation("Tem certeza que deseja sair?"):
                    print_success("Encerrando. Até logo!")
                    logger.info("Ransomware Scanner terminated by user")
                    sys.exit(0)
                continue

            func()
            input("\nPressione ENTER para voltar ao menu...")

        except KeyboardInterrupt:
            print("\n")
            if get_user_confirmation("Interrupção detectada. Deseja sair?"):
                print_success("Encerrando. Até logo!")
                sys.exit(0)
        except Exception as e:
            print_error(f"Erro inesperado: {e}")
            logger.exception(f"Unexpected error in main loop: {e}")


if __name__ == "__main__":
    main()
