# ============================================================================
# ADVANCED FILE SEARCH - RANSOMWARE SCANNER v2.0
# ============================================================================

import fnmatch
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

import utils
from config import ADVANCED_SEARCH_CONFIG

logger = utils.setup_logger('advanced_file_search')

# Diretórios a ignorar por padrão
DEFAULT_EXCLUDE_DIRS = frozenset(ADVANCED_SEARCH_CONFIG.get('exclude_dirs', [
    '.git', '.svn', '.hg',
    'node_modules', '__pycache__', '.tox', '.venv', 'venv', 'env',
    '.idea', '.vscode',
    'quarantine',
]))

# ============================================================================
# RESULTADO
# ============================================================================


def _make_file_entry(path: Path) -> Dict:
    """Constrói dicionário de metadados de um arquivo"""
    try:
        stat = path.stat()
        return {
            'path': str(path.resolve()),
            'name': path.name,
            'extension': path.suffix.lower(),
            'size': stat.st_size,
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }
    except OSError:
        return {
            'path': str(path),
            'name': path.name,
            'extension': path.suffix.lower(),
            'size': 0,
            'modified': '',
            'created': '',
        }


# ============================================================================
# COLETA DE ARQUIVOS (com exclusão de dirs especiais)
# ============================================================================

def _iter_files(
    directory: Union[str, Path],
    recursive: bool = True,
    exclude_dirs: frozenset = DEFAULT_EXCLUDE_DIRS,
) -> List[Path]:
    """
    Itera por arquivos de um diretório, excluindo pastas especiais.

    Returns:
        Lista de Path objects para cada arquivo encontrado.
    """
    root = Path(directory)
    if not root.is_dir():
        logger.warning(f"Diretório não encontrado: {directory}")
        return []

    files: List[Path] = []

    if recursive:
        for entry in root.rglob('*'):
            # Pular se alguma parte do caminho está na lista de exclusão
            if any(part in exclude_dirs for part in entry.parts):
                continue
            if entry.is_file():
                files.append(entry)
    else:
        for entry in root.iterdir():
            if entry.is_file():
                files.append(entry)

    return files


# ============================================================================
# FUNÇÕES PRINCIPAIS DE BUSCA
# ============================================================================

def search_files(
    pattern: str,
    directories: Union[str, List[str]],
    filters: Optional[Dict] = None,
    recursive: bool = True,
    max_workers: int = 4,
) -> List[Dict]:
    """
    Busca arquivos usando glob pattern ou regex em um ou mais diretórios.

    Args:
        pattern: Padrão de busca (ex: '*.exe', '**/malware*', 'ransom.*')
        directories: Diretório ou lista de diretórios para buscar
        filters: Filtros adicionais:
            - 'min_size' (int, bytes)
            - 'max_size' (int, bytes)
            - 'start_date' (str ISO ou datetime)
            - 'end_date' (str ISO ou datetime)
            - 'extensions' (list[str])
        recursive: Busca recursiva (padrão: True)
        max_workers: Threads paralelas para busca

    Returns:
        Lista de dicionários com informações dos arquivos encontrados.
    """
    if isinstance(directories, str):
        directories = [directories]

    filters = filters or {}
    results: List[Dict] = []

    def _search_in_dir(directory: str) -> List[Dict]:
        matches = []
        root = Path(directory)
        if not root.is_dir():
            logger.warning(f"Diretório inválido: {directory}")
            return matches

        try:
            # Usar rglob/glob do pathlib com o padrão diretamente
            if recursive:
                # Suporte a padrões com '**'
                if '**' in pattern:
                    candidates = root.glob(pattern)
                else:
                    candidates = root.rglob(pattern)
            else:
                candidates = root.glob(pattern)

            for path in candidates:
                if not path.is_file():
                    continue
                # Pular dirs excluídos
                if any(part in DEFAULT_EXCLUDE_DIRS for part in path.parts):
                    continue
                entry = _make_file_entry(path)
                if _apply_filters(entry, filters):
                    matches.append(entry)
        except Exception as e:
            logger.error(f"Erro ao buscar em {directory}: {e}")

        return matches

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_search_in_dir, d): d for d in directories}
        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as e:
                logger.error(f"Erro na thread de busca: {e}")

    logger.info(f"Busca '{pattern}' encontrou {len(results)} arquivo(s)")
    return results


def find_by_extension(
    ext: str,
    directories: Union[str, List[str]],
    recursive: bool = True,
) -> List[Dict]:
    """
    Encontra arquivos por extensão em um ou mais diretórios.

    Args:
        ext: Extensão (ex: '.exe', 'py', '.encrypted')
        directories: Diretório ou lista de diretórios
        recursive: Busca recursiva

    Returns:
        Lista de dicionários com informações dos arquivos.
    """
    clean_ext = ext if ext.startswith('.') else f'.{ext}'
    pattern = f'*{clean_ext}'
    return search_files(pattern, directories, recursive=recursive)


def find_by_size(
    directories: Union[str, List[str]],
    min_size: int = 0,
    max_size: Optional[int] = None,
    recursive: bool = True,
) -> List[Dict]:
    """
    Encontra arquivos por intervalo de tamanho.

    Args:
        directories: Diretório ou lista de diretórios
        min_size: Tamanho mínimo em bytes
        max_size: Tamanho máximo em bytes (None = sem limite)
        recursive: Busca recursiva

    Returns:
        Lista de dicionários com informações dos arquivos.
    """
    filters: Dict = {'min_size': min_size}
    if max_size is not None:
        filters['max_size'] = max_size
    return search_files('*', directories, filters=filters, recursive=recursive)


def find_by_date(
    directories: Union[str, List[str]],
    start_date: Optional[Union[str, datetime]] = None,
    end_date: Optional[Union[str, datetime]] = None,
    recursive: bool = True,
) -> List[Dict]:
    """
    Encontra arquivos por data de modificação.

    Args:
        directories: Diretório ou lista de diretórios
        start_date: Data inicial (string ISO ou datetime)
        end_date: Data final (string ISO ou datetime)
        recursive: Busca recursiva

    Returns:
        Lista de dicionários com informações dos arquivos.
    """
    filters: Dict = {}
    if start_date:
        filters['start_date'] = start_date
    if end_date:
        filters['end_date'] = end_date
    return search_files('*', directories, filters=filters, recursive=recursive)


def find_by_regex(
    pattern: str,
    directories: Union[str, List[str]],
    recursive: bool = True,
) -> List[Dict]:
    """
    Encontra arquivos cujo nome corresponde a uma expressão regular.

    Args:
        pattern: Expressão regular para o nome do arquivo
        directories: Diretório ou lista de diretórios
        recursive: Busca recursiva

    Returns:
        Lista de dicionários com informações dos arquivos.
    """
    if isinstance(directories, str):
        directories = [directories]

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        logger.error(f"Regex inválida: {e}")
        return []

    results = []
    for directory in directories:
        files = _iter_files(directory, recursive=recursive)
        for path in files:
            if regex.search(path.name):
                results.append(_make_file_entry(path))

    logger.info(f"Regex '{pattern}' encontrou {len(results)} arquivo(s)")
    return results


# ============================================================================
# FILTROS
# ============================================================================

def _apply_filters(entry: Dict, filters: Dict) -> bool:
    """Aplica filtros ao resultado de busca; retorna True se o arquivo passar"""
    # Filtro de tamanho
    min_size = filters.get('min_size')
    if min_size is not None and entry['size'] < min_size:
        return False

    max_size = filters.get('max_size')
    if max_size is not None and entry['size'] > max_size:
        return False

    # Filtro de extensão
    extensions = filters.get('extensions')
    if extensions:
        clean = [e if e.startswith('.') else f'.{e}' for e in extensions]
        if entry['extension'] not in clean:
            return False

    # Filtro de data
    if entry.get('modified'):
        try:
            modified = datetime.fromisoformat(entry['modified'])

            start_date = filters.get('start_date')
            if start_date:
                if isinstance(start_date, str):
                    start_date = datetime.fromisoformat(start_date)
                if modified < start_date:
                    return False

            end_date = filters.get('end_date')
            if end_date:
                if isinstance(end_date, str):
                    end_date = datetime.fromisoformat(end_date)
                if modified > end_date:
                    return False
        except (ValueError, TypeError):
            pass

    return True


# ============================================================================
# BUSCA COMBINADA (para uso interativo no menu)
# ============================================================================

def advanced_search(
    query: str,
    directories: Union[str, List[str]],
    recursive: bool = True,
    min_size: Optional[int] = None,
    max_size: Optional[int] = None,
    extensions: Optional[List[str]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> List[Dict]:
    """
    Interface unificada para busca avançada de arquivos.

    Args:
        query: Padrão de busca (glob ou extensão). Ex: '*.exe', 'ransom*'
        directories: Diretório(s) para buscar
        recursive: Busca recursiva
        min_size: Tamanho mínimo em bytes
        max_size: Tamanho máximo em bytes
        extensions: Lista de extensões para filtrar
        start_date: Data de modificação inicial (ISO 8601)
        end_date: Data de modificação final (ISO 8601)

    Returns:
        Lista de dicionários com informações dos arquivos encontrados.
    """
    filters: Dict = {}
    if min_size is not None:
        filters['min_size'] = min_size
    if max_size is not None:
        filters['max_size'] = max_size
    if extensions:
        filters['extensions'] = extensions
    if start_date:
        filters['start_date'] = start_date
    if end_date:
        filters['end_date'] = end_date

    return search_files(query, directories, filters=filters, recursive=recursive)


if __name__ == '__main__':
    print("✅ Advanced File Search carregado com sucesso!")
