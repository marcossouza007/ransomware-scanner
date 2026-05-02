# 🛡️ Ransomware Scanner & Recovery Tool v2.0

Aplicação completa integrada para **detecção, isolamento e recuperação de ransomware** com interface CLI amigável e relatórios profissionais.

## ✨ Funcionalidades

### 🔍 Scanner de Ransomware
- ✅ Análise de entropia Shannon (detecção de criptografia)
- ✅ Detecção de extensões suspeitas (.locked, .encrypted, etc)
- ✅ Busca de palavras-chave de malware em arquivo
- ✅ Score de risco calculado com múltiplos critérios (0-1)
- ✅ Classificação automática de tipos de ameaça
- ✅ Scan recursivo de diretórios

### 🔒 Quarentena Avançada
- ✅ Mover arquivos para `/quarantine` com estrutura organizada
- ✅ **3 categorias de organização:**
  - `by_type/` (ransomware, trojan, wiper, etc)
  - `by_date/` (YYYY-MM-DD)
  - `by_risk/` (critical, high, medium, low)
- ✅ Armazenar metadados completos (SHA256, risk_score, timestamp)
- ✅ Restauração de arquivos
- ✅ Relatório JSON de quarentena

### 🔐 Sobrescrita Segura
- ✅ **8 métodos de delete seguro:**
  - SIMPLE_ZEROS (1 pass)
  - RANDOM (1 pass)
  - **DOD_5220_22 (3 passes)** - RECOMENDADO ⭐
  - SCHNEIER (7 passes)
  - GUTMANN (35 passes) - MÁXIMO 🔒
  - DBAN (4 passes)
  - NIST (3 passes)
- ✅ Sobrescrita antes de deletar
- ✅ Logging completo

### 🔓 Descriptografia
- ✅ Suporte a chaves conhecidas (WannaCry, Petya, Lockit, Cerber, Shade, Generic)
- ✅ Métodos: XOR e AES
- ✅ Recuperação de backups
- ✅ Tentativa automática de todos os tipos

### 📄 Relatórios em PDF
- ✅ Gráficos profissionais:
  - Pizza Chart - Distribuição de risco
  - Bar Chart - Tipos de ameaça
  - Line Chart - Timeline de detecção
- ✅ Tabelas formatadas com cores
- ✅ Resumo executivo
- ✅ Recomendações de segurança
- ✅ 3 tipos: Scan, Quarentena, Recuperação

### 🎯 Interface CLI Interativa
- ✅ Menu principal com 8 opções
- ✅ Escanear diretório com parâmetros customizáveis
- ✅ Visualizar ameaças detectadas com detalhes
- ✅ Gerenciar quarentena (listar, restaurar)
- ✅ Gerar relatórios (JSON + PDF)
- ✅ Estatísticas e análises
- ✅ Configurações personalizáveis

## 📦 Instalação

### Requisitos
- Python 3.8+
- pip

### Passos

```bash
# 1. Clonar repositório
git clone https://github.com/marcossouza007/ransomware-scanner.git
cd ransomware-scanner

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Executar aplicação
python main.py
```

## 🚀 Uso Rápido

```bash
$ python main.py

================================================================================
        🛡️  RANSOMWARE SCANNER & RECOVERY TOOL v2.0
================================================================================

Menu Principal:

1. 🔍 Escanear Diretório
2. 📋 Ver Ameaças Detectadas
3. 🔐 Tentar Recuperação
4. 🔒 Gerenciar Quarentena
5. 📄 Gerar Relatórios PDF
6. 📊 Ver Estatísticas
7. ⚙️  Configurações
8. ✖️  Sair

Escolha uma opção: 1
```

## 📂 Estrutura de Diretórios

```
quarantine/
├── .metadata/               # JSON com metadados
├── by_type/
│   ├── ransomware/exe/     # Organizados por tipo + extensão
│   ├── trojan/dll/
│   └── wiper/bin/
├── by_date/
│   └── 2026-05-02/         # Organizados por data
└── by_risk/
    ├── critical/           # Risco > 0.75
    ├── high/               # Risco 0.45-0.75
    ├── medium/             # Risco 0.25-0.45
    └── low/                # Risco < 0.25

reports/
├── *.json                  # Relatórios JSON
├── *.pdf                   # Relatórios PDF
└── charts/
    ├── chart_risk_distribution.png
    ├── chart_threat_types.png
    └── chart_timeline.png

logs/
└── ransomware_scanner.log  # Log completo
```

## 🔧 Configuração

Edite `config.py` para personalizar:

```python
# Threshold de detecção
SCAN_CONFIG = {
    'threat_threshold': 0.5,  # Ameaças com score > 0.5
    'block_size': 4096,
    'recursive': True
}

# Método de sobrescrita padrão
DEFAULT_OVERWRITE_METHOD = SecureOverwriteMethod.DOD_5220_22  # Recomendado
```

## 📊 Classificação de Risco

| Nível | Range | Símbolo | Cor | Ação |
|-------|-------|---------|-----|------|
| CRÍTICO | > 0.75 | 🔴 | Vermelho | Quarentena + Delete |
| ALTO | 0.45-0.75 | 🟠 | Laranja | Quarentena |
| MÉDIO | 0.25-0.45 | 🟡 | Amarelo | Monitorar |
| BAIXO | < 0.25 | 🟢 | Verde | Ignorar |

## 🔐 Métodos de Sobrescrita Segura

| Método | Passes | Nível | Tempo | Recomendado |
|--------|--------|-------|-------|-------------|
| SIMPLE_ZEROS | 1 | Baixo | Muito Rápido | ❌ |
| RANDOM | 1 | Médio | Rápido | ⚠️ |
| DOD_5220_22 | 3 | Alto | Normal | ✅ **SIM** |
| SCHNEIER | 7 | Muito Alto | Lento | ⚠️ |
| GUTMANN | 35 | Máximo | Muito Lento | 🔒 Ultra |
| DBAN | 4 | Alto | Lento | ⚠️ |
| NIST | 3 | Alto | Normal | ⚠️ |

## 📈 Exemplo de Score de Risco

**Cálculo:**
```python
risk_score = (
    entropy_score * 0.35 +      # Entropia (35%)
    spike_score * 0.15 +        # Variação (15%)
    keyword_score * 0.25 +      # Palavras-chave (25%)
    ext_score * 0.25            # Extensão suspeita (25%)
)
```

## 🛠️ Troubleshooting

### Erro: `pycryptodome não instalado`
```bash
pip install pycryptodome
```

### Erro: `Permissão negada ao deletar arquivo`
- Execute como administrador/root
- Verifique permissões do arquivo

### Erro: `Relatório PDF não gerado`
- Verifique espaço em disco
- Verifique permissões de escrita

## 📝 Logging

Todos os eventos são registrados em `logs/ransomware_scanner.log`:
- ✅ Scans iniciados/concluídos
- ✅ Arquivos em quarentena
- ✅ Deletions seguras
- ✅ Tentativas de descriptografia
- ✅ Erros e exceções

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📄 Licença

MIT License - Veja LICENSE para detalhes

## ⚠️ Disclaimer

Esta ferramenta é fornecida **COMO ESTÁ**, sem garantias. Use por sua conta e risco.

**Use apenas em seus próprios sistemas ou com permissão explícita.**

---

**Versão:** 2.0  
**Data:** 2026-05-02  
**Status:** ✅ Estável
