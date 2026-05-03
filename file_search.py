# ============================================================================
# FILE SEARCH MODULE - RANSOMWARE SCANNER v2.0
# Sistema Avançado de Busca de Arquivos, Pastas e Pacotes
# 100% portável com pathlib (Windows, Linux, macOS)
# ============================================================================

import re
import zipfile
import tarfile
import fnmatch
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from utils import logger, format_bytes

# ============================================================================
# CONSTANTES INTERNAS
# ============================================================================

# Extensões de pacotes suportados nativamente (sem dependências externas)
_PACKAGE_EXTENSIONS = {'.zip', '.tar', '.gz', '.bz2', '.xz', '.tgz'}

# Diretórios especiais ignorados por padrão
_DEFAULT_EXCLUDE_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', '.env'}


# ============================================================================
# CLASSE PRINCIPAL
# ============================================================================

class AdvancedFileSearch:
    """
    Sistema avançado de busca de arquivos, pastas e pacotes usando pathlib.
    Portável para Windows, Linux e macOS sem dependência de dir/cd.
    """

    def __init__(
        self,
        exclude_dirs: Optional[List[str]] = None,
        max_depth: Optional[int] = None,
        follow_symlinks: bool = False,
    ):
        """
        Inicializa o buscador.

        Args:
            exclude_dirs: Nomes de diretórios a ignorar durante a busca.
            max_depth: Profundidade máxima de recursão (None = ilimitado).
            follow_symlinks: Se True, segue links simbólicos.
        """
        self.exclude_dirs: set = set(exclude_dirs or []) | _DEFAULT_EXCLUDE_DIRS
        self.max_depth = max_depth
        self.follow_symlinks = follow_symlinks
        self._cancel_event = threading.Event()

    # ------------------------------------------------------------------
    # CONTROLE
    # ------------------------------------------------------------------

    def cancel(self):
        """Cancela uma busca em andamento (thread-safe)."""
        self._cancel_event.set()

    def _reset(self):
        """Reseta estado de cancelamento antes de uma nova busca."""
        self._cancel_event.clear()

    # ------------------------------------------------------------------
    # ITERADORES INTERNOS
    # ------------------------------------------------------------------

    def _iter_files(
        self,
        start_path: Path,
        recursive: bool = True,
        current_depth: int = 0,
    ):
        """Itera recursivamente sobre arquivos respeitando exclusões e profundidade."""
        try:
            entries = list(start_path.iterdir())
        except PermissionError:
            logger.debug(f"Sem permissão para acessar: {start_path}")
            return

        for entry in entries:
            if self._cancel_event.is_set():
                return
            try:
                if entry.is_symlink() and not self.follow_symlinks:
                    continue
                if entry.is_dir():
                    if entry.name in self.exclude_dirs:
                        continue
                    if recursive:
                        next_depth = current_depth + 1
                        if self.max_depth is None or next_depth <= self.max_depth:
                            yield from self._iter_files(entry, recursive, next_depth)
                elif entry.is_file():
                    yield entry
            except (PermissionError, OSError):
                logger.debug(f"Erro ao acessar: {entry}")

    def _iter_dirs(
        self,
        start_path: Path,
        recursive: bool = True,
        current_depth: int = 0,
    ):
        """Itera recursivamente sobre diretórios."""
        try:
            entries = list(start_path.iterdir())
        except PermissionError:
            logger.debug(f"Sem permissão para acessar: {start_path}")
            return

        for entry in entries:
            if self._cancel_event.is_set():
                return
            try:
                if entry.is_symlink() and not self.follow_symlinks:
                    continue
                if entry.is_dir():
                    if entry.name in self.exclude_dirs:
                        continue
                    yield entry, current_depth + 1
                    if recursive:
                        next_depth = current_depth + 1
                        if self.max_depth is None or next_depth < self.max_depth:
                            yield from self._iter_dirs(entry, recursive, next_depth)
            except (PermissionError, OSError):
                logger.debug(f"Erro ao acessar: {entry}")

    # ------------------------------------------------------------------
    # BUSCA POR PADRÃO (GLOB / REGEX)
    # ------------------------------------------------------------------

    def search_by_pattern(
        self,
        pattern: str,
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Busca arquivos por padrão glob ou regex.

        Args:
            pattern: Padrão glob (e.g., '*.exe') ou regex delimitado por /…/
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários com informações dos arquivos encontrados.
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        # Detectar se é regex (/pattern/)
        is_regex = pattern.startswith('/') and pattern.endswith('/')
        if is_regex:
            try:
                regex = re.compile(pattern[1:-1], re.IGNORECASE)
            except re.error as exc:
                logger.error(f"Regex inválida '{pattern}': {exc}")
                return []

        results = []
        for file_path in self._iter_files(root, recursive):
            name = file_path.name
            if is_regex:
                matched = bool(regex.search(name))
            else:
                matched = fnmatch.fnmatch(name.lower(), pattern.lower())
            if matched:
                results.append(_file_info(file_path))

        logger.info(f"search_by_pattern('{pattern}', '{start_path}'): {len(results)} resultados")
        return results

    # ------------------------------------------------------------------
    # BUSCA POR EXTENSÃO
    # ------------------------------------------------------------------

    def search_by_extension(
        self,
        extensions: List[str],
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Busca arquivos por extensão(ões).

        Args:
            extensions: Lista de extensões, e.g. ['.exe', '.dll'].
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários com informações dos arquivos encontrados.
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        exts = {ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in extensions}
        results = []
        for file_path in self._iter_files(root, recursive):
            if file_path.suffix.lower() in exts:
                results.append(_file_info(file_path))

        logger.info(f"search_by_extension({extensions}, '{start_path}'): {len(results)} resultados")
        return results

    # ------------------------------------------------------------------
    # BUSCA POR TAMANHO
    # ------------------------------------------------------------------

    def search_by_size(
        self,
        min_size: Optional[int],
        max_size: Optional[int],
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Busca arquivos por intervalo de tamanho em bytes.

        Args:
            min_size: Tamanho mínimo em bytes (None = sem limite inferior).
            max_size: Tamanho máximo em bytes (None = sem limite superior).
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários com informações dos arquivos encontrados.
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        results = []
        for file_path in self._iter_files(root, recursive):
            try:
                size = file_path.stat().st_size
                if min_size is not None and size < min_size:
                    continue
                if max_size is not None and size > max_size:
                    continue
                results.append(_file_info(file_path))
            except OSError:
                continue

        logger.info(f"search_by_size({min_size}, {max_size}, '{start_path}'): {len(results)} resultados")
        return results

    # ------------------------------------------------------------------
    # BUSCA POR DATA DE MODIFICAÇÃO
    # ------------------------------------------------------------------

    def search_by_date(
        self,
        start_date: Optional[str],
        end_date: Optional[str],
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Busca arquivos por data de modificação.

        Args:
            start_date: Data início no formato 'YYYY-MM-DD' (None = sem limite).
            end_date: Data fim no formato 'YYYY-MM-DD' (None = sem limite).
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários com informações dos arquivos encontrados.
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        ts_start = _parse_date(start_date)
        ts_end = _parse_date(end_date, end_of_day=True)

        results = []
        for file_path in self._iter_files(root, recursive):
            try:
                mtime = file_path.stat().st_mtime
                if ts_start is not None and mtime < ts_start:
                    continue
                if ts_end is not None and mtime > ts_end:
                    continue
                results.append(_file_info(file_path))
            except OSError:
                continue

        logger.info(f"search_by_date('{start_date}', '{end_date}', '{start_path}'): {len(results)} resultados")
        return results

    # ------------------------------------------------------------------
    # BUSCA POR NOME DE ARQUIVO
    # ------------------------------------------------------------------

    def search_by_filename(
        self,
        filename_pattern: str,
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Busca por nome de arquivo com suporte a wildcards (*?).

        Args:
            filename_pattern: Padrão de nome, e.g. 'malware*', 'config.ini'.
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários com informações dos arquivos encontrados.
        """
        return self.search_by_pattern(filename_pattern, start_path, recursive)

    # ------------------------------------------------------------------
    # BUSCA AVANÇADA (MÚLTIPLOS CRITÉRIOS)
    # ------------------------------------------------------------------

    def advanced_search(
        self,
        criteria: Dict[str, Any],
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Busca combinando múltiplos critérios.

        Args:
            criteria: Dicionário com um ou mais dos seguintes campos:
                - 'pattern' (str): Padrão glob ou /regex/
                - 'extensions' (list): Lista de extensões
                - 'min_size' (int): Tamanho mínimo em bytes
                - 'max_size' (int): Tamanho máximo em bytes
                - 'start_date' (str): Data início 'YYYY-MM-DD'
                - 'end_date' (str): Data fim 'YYYY-MM-DD'
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários com informações dos arquivos encontrados.

        Example::

            criteria = {
                'extensions': ['.exe', '.dll'],
                'min_size': 1024,
                'max_size': 100 * 1024 * 1024,
                'start_date': '2026-01-01',
                'end_date': '2026-05-03',
            }
            results = searcher.advanced_search(criteria, '/home/user')
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        pattern: Optional[str] = criteria.get('pattern')
        extensions = criteria.get('extensions')
        min_size: Optional[int] = criteria.get('min_size')
        max_size: Optional[int] = criteria.get('max_size')
        start_date: Optional[str] = criteria.get('start_date')
        end_date: Optional[str] = criteria.get('end_date')

        # Pre-compilar regex / extensões
        is_regex = pattern is not None and pattern.startswith('/') and pattern.endswith('/')
        compiled_re = None
        if is_regex:
            try:
                compiled_re = re.compile(pattern[1:-1], re.IGNORECASE)
            except re.error as exc:
                logger.error(f"Regex inválida '{pattern}': {exc}")
                return []

        exts: Optional[set] = None
        if extensions:
            exts = {ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in extensions}

        ts_start = _parse_date(start_date)
        ts_end = _parse_date(end_date, end_of_day=True)

        results = []
        for file_path in self._iter_files(root, recursive):
            try:
                # Filtro por padrão / nome
                if pattern:
                    name = file_path.name
                    if is_regex:
                        if not compiled_re.search(name):
                            continue
                    else:
                        if not fnmatch.fnmatch(name.lower(), pattern.lower()):
                            continue

                # Filtro por extensão
                if exts and file_path.suffix.lower() not in exts:
                    continue

                stat = file_path.stat()

                # Filtro por tamanho
                if min_size is not None and stat.st_size < min_size:
                    continue
                if max_size is not None and stat.st_size > max_size:
                    continue

                # Filtro por data
                if ts_start is not None and stat.st_mtime < ts_start:
                    continue
                if ts_end is not None and stat.st_mtime > ts_end:
                    continue

                results.append(_file_info(file_path))

            except OSError:
                continue

        logger.info(f"advanced_search({criteria}, '{start_path}'): {len(results)} resultados")
        return results

    # ------------------------------------------------------------------
    # LISTAGEM DE DIRETÓRIOS
    # ------------------------------------------------------------------

    def list_directories(
        self,
        start_path: str,
        recursive: bool = True,
        max_depth: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Lista diretórios com metadados (tamanho total, nº de arquivos, profundidade).

        Args:
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.
            max_depth: Profundidade máxima (None = ilimitado).

        Returns:
            Lista de dicionários com informações de cada diretório.
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        # Sobrepor max_depth temporariamente se passado aqui
        old_depth = self.max_depth
        if max_depth is not None:
            self.max_depth = max_depth

        results = []
        for dir_path, depth in self._iter_dirs(root, recursive):
            try:
                info = _dir_info(dir_path, depth)
                results.append(info)
            except OSError:
                continue

        self.max_depth = old_depth
        logger.info(f"list_directories('{start_path}'): {len(results)} diretórios")
        return results

    def print_directory_tree(
        self,
        start_path: str,
        max_depth: Optional[int] = 3,
    ):
        """
        Imprime árvore de diretórios com indentação visual.

        Args:
            start_path: Caminho inicial.
            max_depth: Profundidade máxima (None = ilimitado).
        """
        root = Path(start_path).resolve()
        print(f"\n📁 {root}")
        dirs = self.list_directories(str(root), recursive=True, max_depth=max_depth)
        for info in dirs:
            depth = info['depth']
            indent = "  " * depth
            name = Path(info['path']).name
            n_files = info['file_count']
            size_str = format_bytes(info['total_size_bytes'])
            print(f"{indent}📂 {name}  ({n_files} arquivos, {size_str})")

    # ------------------------------------------------------------------
    # LISTAGEM DE PACOTES
    # ------------------------------------------------------------------

    def list_packages(
        self,
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Lista arquivos compactados (.zip, .tar, .tar.gz, .tgz, .bz2, .xz).

        Args:
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários com informações de cada pacote.
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        results = []
        for file_path in self._iter_files(root, recursive):
            if _is_package(file_path):
                info = _file_info(file_path)
                info['package_type'] = _package_type(file_path)
                info['contents'] = _list_package_contents(file_path)
                results.append(info)

        logger.info(f"list_packages('{start_path}'): {len(results)} pacotes")
        return results

    # ------------------------------------------------------------------
    # BUSCA DENTRO DE PACOTES
    # ------------------------------------------------------------------

    def search_in_packages(
        self,
        pattern: str,
        start_path: str,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Busca por padrão glob dentro de arquivos compactados (sem extração).

        Args:
            pattern: Padrão glob, e.g. 'malware*.exe', ou regex /…/.
            start_path: Caminho inicial de busca.
            recursive: Se True, percorre subdiretórios.

        Returns:
            Lista de dicionários descrevendo as entradas encontradas nos pacotes.

        Example::

            results = searcher.search_in_packages('*.virus', '/downloads')
        """
        self._reset()
        root = Path(start_path).resolve()
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {start_path}")
            return []

        is_regex = pattern.startswith('/') and pattern.endswith('/')
        compiled_re = None
        if is_regex:
            try:
                compiled_re = re.compile(pattern[1:-1], re.IGNORECASE)
            except re.error as exc:
                logger.error(f"Regex inválida '{pattern}': {exc}")
                return []

        results = []
        for file_path in self._iter_files(root, recursive):
            if not _is_package(file_path):
                continue
            for entry_name, entry_size in _list_package_contents(file_path):
                base_name = Path(entry_name).name
                if is_regex:
                    matched = bool(compiled_re.search(base_name))
                else:
                    matched = fnmatch.fnmatch(base_name.lower(), pattern.lower())
                if matched:
                    results.append({
                        'package_path': str(file_path),
                        'entry_name': entry_name,
                        'entry_size_bytes': entry_size,
                        'entry_size': format_bytes(entry_size) if entry_size is not None else 'N/A',
                        'package_type': _package_type(file_path),
                    })

        logger.info(f"search_in_packages('{pattern}', '{start_path}'): {len(results)} entradas")
        return results


# ============================================================================
# FUNÇÕES AUXILIARES INTERNAS
# ============================================================================

def _file_info(file_path: Path) -> Dict[str, Any]:
    """Retorna dicionário com metadados de um arquivo."""
    try:
        stat = file_path.stat()
        return {
            'path': str(file_path),
            'name': file_path.name,
            'extension': file_path.suffix.lower(),
            'size_bytes': stat.st_size,
            'size': format_bytes(stat.st_size),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }
    except OSError:
        return {
            'path': str(file_path),
            'name': file_path.name,
            'extension': file_path.suffix.lower(),
            'size_bytes': 0,
            'size': '0 B',
            'modified': '',
            'created': '',
        }


def _dir_info(dir_path: Path, depth: int) -> Dict[str, Any]:
    """Retorna dicionário com metadados de um diretório."""
    file_count = 0
    total_size = 0
    try:
        for entry in dir_path.iterdir():
            if entry.is_file():
                file_count += 1
                try:
                    total_size += entry.stat().st_size
                except OSError:
                    pass
    except PermissionError:
        pass
    return {
        'path': str(dir_path),
        'name': dir_path.name,
        'depth': depth,
        'file_count': file_count,
        'total_size_bytes': total_size,
        'total_size': format_bytes(total_size),
    }


def _is_package(file_path: Path) -> bool:
    """Retorna True se o arquivo é um pacote compactado suportado."""
    suffixes = ''.join(file_path.suffixes).lower()
    return (
        file_path.suffix.lower() in _PACKAGE_EXTENSIONS
        or suffixes.endswith('.tar.gz')
        or suffixes.endswith('.tar.bz2')
        or suffixes.endswith('.tar.xz')
    )


def _package_type(file_path: Path) -> str:
    """Retorna string descrevendo o tipo de pacote."""
    suffixes = ''.join(file_path.suffixes).lower()
    if suffixes.endswith('.tar.gz') or suffixes.endswith('.tgz'):
        return 'tar.gz'
    if suffixes.endswith('.tar.bz2'):
        return 'tar.bz2'
    if suffixes.endswith('.tar.xz'):
        return 'tar.xz'
    return file_path.suffix.lower().lstrip('.')


def _list_package_contents(file_path: Path) -> List[Tuple[str, Optional[int]]]:
    """
    Lista entradas de um pacote compactado.
    Retorna lista de (nome_entrada, tamanho_em_bytes).
    """
    entries: List[Tuple[str, Optional[int]]] = []
    try:
        if zipfile.is_zipfile(str(file_path)):
            with zipfile.ZipFile(str(file_path), 'r') as zf:
                for info in zf.infolist():
                    entries.append((info.filename, info.file_size))
            return entries
    except Exception as exc:
        logger.debug(f"Erro ao abrir zip {file_path}: {exc}")

    try:
        if tarfile.is_tarfile(str(file_path)):
            with tarfile.open(str(file_path), 'r:*') as tf:
                for member in tf.getmembers():
                    entries.append((member.name, member.size))
            return entries
    except Exception as exc:
        logger.debug(f"Erro ao abrir tar {file_path}: {exc}")

    return entries


def _parse_date(date_str: Optional[str], end_of_day: bool = False) -> Optional[float]:
    """Converte string 'YYYY-MM-DD' para timestamp Unix."""
    if date_str is None:
        return None
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%d')
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt.timestamp()
    except ValueError:
        logger.warning(f"Data inválida '{date_str}', esperado formato YYYY-MM-DD")
        return None


# ============================================================================
# SAÍDA / FORMATAÇÃO
# ============================================================================

def print_results_table(results: List[Dict[str, Any]], title: str = "Resultados"):
    """Imprime resultados em tabela formatada no terminal."""
    if not results:
        print(f"\n⚠️  Nenhum resultado encontrado.")
        return

    print(f"\n{'='*80}")
    print(f"  {title}  ({len(results)} item(ns))")
    print(f"{'='*80}")
    print(f"{'#':<4} {'Nome':<30} {'Tamanho':>10}  {'Modificado':<22}  Caminho")
    print(f"{'-'*4} {'-'*30} {'-'*10}  {'-'*22}  {'-'*30}")
    for idx, item in enumerate(results, 1):
        name = item.get('name', Path(item['path']).name)[:28]
        size = item.get('size', '')
        modified = item.get('modified', '')[:19] if item.get('modified') else ''
        path = item['path']
        print(f"{idx:<4} {name:<30} {size:>10}  {modified:<22}  {path}")
    print(f"{'='*80}")


if __name__ == '__main__':
    print("✅ file_search module loaded successfully!")
