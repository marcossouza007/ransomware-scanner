# ============================================================================
# GERADOR DE RELATÓRIOS PDF - RANSOMWARE SCANNER v2.0
# ============================================================================

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from config import REPORTS_DIR, CHARTS_DIR, RISK_LEVELS

# ============================================================================
# 1. GERADOR DE GRÁFICOS
# ============================================================================

class ChartGenerator:
    """Gera gráficos profissionais para relatórios"""

    def __init__(self, output_dir: str = str(CHARTS_DIR)):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_risk_pie_chart(
        self,
        risk_data: Dict[str, int],
        output_file: str = 'chart_risk_distribution.png'
    ) -> Optional[str]:
        """Gera gráfico de pizza para distribuição de risco"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt

            labels = []
            sizes = []
            colors_list = []
            color_map = {
                'critical': '#FF0000',
                'high': '#FF8C00',
                'medium': '#FFD700',
                'low': '#90EE90',
            }

            for category, count in risk_data.items():
                if count > 0:
                    labels.append(f"{category.capitalize()} ({count})")
                    sizes.append(count)
                    colors_list.append(color_map.get(category, '#AAAAAA'))

            if not sizes:
                return None

            fig, ax = plt.subplots(figsize=(8, 6))
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors_list,
                autopct='%1.1f%%',
                startangle=140,
                pctdistance=0.85
            )

            for text in autotexts:
                text.set_fontsize(10)
                text.set_fontweight('bold')

            ax.set_title('Distribuição de Risco por Categoria', fontsize=14, fontweight='bold', pad=15)
            plt.tight_layout()

            filepath = self.output_dir / output_file
            plt.savefig(str(filepath), dpi=150, bbox_inches='tight')
            plt.close()

            return str(filepath)

        except ImportError:
            print("⚠️  matplotlib não instalado. Gráficos desativados.")
            return None
        except Exception as e:
            print(f"❌ Erro ao gerar gráfico de pizza: {e}")
            return None

    def generate_threat_bar_chart(
        self,
        threat_data: Dict[str, int],
        output_file: str = 'chart_threat_types.png'
    ) -> Optional[str]:
        """Gera gráfico de barras para tipos de ameaça"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import numpy as np

            if not threat_data:
                return None

            names = list(threat_data.keys())
            values = list(threat_data.values())

            fig, ax = plt.subplots(figsize=(10, 6))
            bar_colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db', '#9b59b6', '#1abc9c']
            bars = ax.bar(
                names,
                values,
                color=bar_colors[:len(names)],
                edgecolor='black',
                linewidth=0.7
            )

            for bar in bars:
                height = bar.get_height()
                ax.annotate(
                    f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords='offset points',
                    ha='center',
                    va='bottom',
                    fontsize=11,
                    fontweight='bold'
                )

            ax.set_xlabel('Tipo de Ameaça', fontsize=12)
            ax.set_ylabel('Quantidade', fontsize=12)
            ax.set_title('Ameaças por Tipo', fontsize=14, fontweight='bold')
            ax.set_ylim(0, max(values) * 1.2 + 1)
            plt.xticks(rotation=20, ha='right')
            plt.tight_layout()

            filepath = self.output_dir / output_file
            plt.savefig(str(filepath), dpi=150, bbox_inches='tight')
            plt.close()

            return str(filepath)

        except ImportError:
            print("⚠️  matplotlib não instalado. Gráficos desativados.")
            return None
        except Exception as e:
            print(f"❌ Erro ao gerar gráfico de barras: {e}")
            return None

    def generate_timeline_chart(
        self,
        threats: List[Dict],
        output_file: str = 'chart_timeline.png'
    ) -> Optional[str]:
        """Gera gráfico de linha (timeline) de detecções"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates
            from collections import Counter

            if not threats:
                return None

            timestamps = []
            for threat in threats:
                ts = threat.get('timestamp') or threat.get('quarantined_at')
                if ts:
                    try:
                        timestamps.append(datetime.fromisoformat(ts))
                    except Exception:
                        pass

            if not timestamps:
                return None

            # Agrupa por hora
            hour_counts: Counter = Counter()
            for ts in timestamps:
                hour_counts[ts.replace(minute=0, second=0, microsecond=0)] += 1

            sorted_hours = sorted(hour_counts.keys())
            counts = [hour_counts[h] for h in sorted_hours]

            fig, ax = plt.subplots(figsize=(12, 5))
            ax.plot(sorted_hours, counts, marker='o', color='#e74c3c', linewidth=2, markersize=7)
            ax.fill_between(sorted_hours, counts, alpha=0.2, color='#e74c3c')

            ax.xaxis.set_major_formatter(mdates.DateFormatter('%d/%m %H:%M'))
            plt.gcf().autofmt_xdate()

            ax.set_xlabel('Data / Hora', fontsize=12)
            ax.set_ylabel('Detecções', fontsize=12)
            ax.set_title('Timeline de Detecções', fontsize=14, fontweight='bold')
            ax.grid(True, linestyle='--', alpha=0.5)
            plt.tight_layout()

            filepath = self.output_dir / output_file
            plt.savefig(str(filepath), dpi=150, bbox_inches='tight')
            plt.close()

            return str(filepath)

        except ImportError:
            print("⚠️  matplotlib não instalado. Gráficos desativados.")
            return None
        except Exception as e:
            print(f"❌ Erro ao gerar timeline: {e}")
            return None


# ============================================================================
# 2. GERADOR DE RELATÓRIOS PDF
# ============================================================================

class PDFReportGenerator:
    """Gera relatórios PDF profissionais"""

    def __init__(self, output_dir: str = str(REPORTS_DIR)):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.chart_generator = ChartGenerator()

    # ------------------------------------------------------------------
    # Helpers ReportLab
    # ------------------------------------------------------------------

    def _get_styles(self):
        """Retorna estilos do ReportLab"""
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Title'],
            fontSize=20,
            spaceAfter=12,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER
        ))
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=colors.HexColor('#2c3e50'),
            spaceBefore=10,
            spaceAfter=6,
            borderPad=4,
        ))
        styles.add(ParagraphStyle(
            name='BodySmall',
            parent=styles['Normal'],
            fontSize=9,
            spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name='Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER,
        ))
        return styles

    def _build_threat_table(self, threats: List[Dict], styles):
        """Constrói tabela de ameaças para o PDF"""
        from reportlab.platypus import Table, TableStyle, Paragraph
        from reportlab.lib import colors

        headers = ['Arquivo', 'Risco', 'Tipo', 'Extensão', 'Tamanho']
        data = [headers]

        for threat in threats[:50]:  # Limite de 50 linhas
            filename = Path(threat.get('path', 'N/A')).name
            risk = f"{threat.get('risk_score', 0):.1%}"
            threat_type = threat.get('threat_type', 'unknown')
            extension = threat.get('extension', 'N/A')
            size_bytes = threat.get('size', 0)
            size_str = _fmt_bytes(size_bytes)
            data.append([filename, risk, threat_type, extension, size_str])

        col_widths = [200, 55, 80, 70, 65]
        table = Table(data, colWidths=col_widths)

        risk_color_map = {'critical': '#FF6B6B', 'high': '#FFA500', 'medium': '#FFD700', 'low': '#90EE90'}

        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f2f2f2')]),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]

        for row_idx, threat in enumerate(threats[:50], start=1):
            score = threat.get('risk_score', 0)
            if score >= 0.75:
                cat = 'critical'
            elif score >= 0.45:
                cat = 'high'
            elif score >= 0.25:
                cat = 'medium'
            else:
                cat = 'low'
            style_cmds.append(
                ('BACKGROUND', (1, row_idx), (1, row_idx), colors.HexColor(risk_color_map[cat]))
            )

        table.setStyle(TableStyle(style_cmds))
        return table

    # ------------------------------------------------------------------
    # Relatório de Scan
    # ------------------------------------------------------------------

    def generate_scan_report(
        self,
        scan_data: Dict[str, Any],
        output_file: str = 'scan_report.pdf'
    ) -> Optional[str]:
        """Gera relatório PDF de scan"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Image, HRFlowable
            )
            from reportlab.lib.units import cm
            from reportlab.lib import colors

        except ImportError:
            print("⚠️  reportlab não instalado. Instale com: pip install reportlab")
            return None

        try:
            filepath = self.output_dir / output_file
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm
            )

            styles = self._get_styles()
            story = []

            # --- Cabeçalho ---
            story.append(Paragraph('🛡️ Ransomware Scanner', styles['CustomTitle']))
            story.append(Paragraph('Relatório de Scan', styles['CustomTitle']))
            story.append(Paragraph(
                f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}",
                styles['Footer']
            ))
            story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#2c3e50')))
            story.append(Spacer(1, 0.4 * cm))

            # --- Resumo Executivo ---
            story.append(Paragraph('Resumo Executivo', styles['SectionHeader']))
            threats = scan_data.get('threats', [])
            total = len(threats)
            duration = scan_data.get('scan_duration', 0)

            story.append(Paragraph(
                f"Total de ameaças detectadas: <b>{total}</b> | "
                f"Duração do scan: <b>{duration:.1f}s</b>",
                styles['BodySmall']
            ))
            story.append(Spacer(1, 0.3 * cm))

            # --- Estatísticas por risco ---
            by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            by_type: Dict[str, int] = {}
            for t in threats:
                score = t.get('risk_score', 0)
                if score >= 0.75:
                    by_risk['critical'] += 1
                elif score >= 0.45:
                    by_risk['high'] += 1
                elif score >= 0.25:
                    by_risk['medium'] += 1
                else:
                    by_risk['low'] += 1
                ttype = t.get('threat_type', 'unknown')
                by_type[ttype] = by_type.get(ttype, 0) + 1

            # Gráficos
            pie_path = self.chart_generator.generate_risk_pie_chart(by_risk)
            bar_path = self.chart_generator.generate_threat_bar_chart(by_type)
            timeline_path = self.chart_generator.generate_timeline_chart(threats)

            story.append(Paragraph('Distribuição de Risco', styles['SectionHeader']))
            if pie_path and os.path.exists(pie_path):
                story.append(Image(pie_path, width=12 * cm, height=8 * cm))

            story.append(Paragraph('Tipos de Ameaça', styles['SectionHeader']))
            if bar_path and os.path.exists(bar_path):
                story.append(Image(bar_path, width=14 * cm, height=7 * cm))

            story.append(Paragraph('Timeline de Detecções', styles['SectionHeader']))
            if timeline_path and os.path.exists(timeline_path):
                story.append(Image(timeline_path, width=15 * cm, height=6 * cm))

            # --- Tabela de ameaças ---
            if threats:
                story.append(Paragraph('Detalhes das Ameaças', styles['SectionHeader']))
                story.append(self._build_threat_table(threats, styles))

            # --- Recomendações ---
            story.append(Spacer(1, 0.4 * cm))
            story.append(Paragraph('Recomendações', styles['SectionHeader']))
            recs = _get_recommendations(by_risk)
            for rec in recs:
                story.append(Paragraph(f"• {rec}", styles['BodySmall']))

            doc.build(story)
            print(f"✅ Relatório de Scan PDF gerado: {filepath}")
            return str(filepath)

        except Exception as e:
            print(f"❌ Erro ao gerar relatório PDF de scan: {e}")
            return None

    # ------------------------------------------------------------------
    # Relatório de Quarentena
    # ------------------------------------------------------------------

    def generate_quarantine_report(
        self,
        quarantine_data: Dict[str, Any],
        output_file: str = 'quarantine_report.pdf'
    ) -> Optional[str]:
        """Gera relatório PDF de quarentena"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Image, HRFlowable, Table, TableStyle
            )
            from reportlab.lib.units import cm
            from reportlab.lib import colors

        except ImportError:
            print("⚠️  reportlab não instalado. Instale com: pip install reportlab")
            return None

        try:
            filepath = self.output_dir / output_file
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm
            )

            styles = self._get_styles()
            story = []

            story.append(Paragraph('🔒 Ransomware Scanner', styles['CustomTitle']))
            story.append(Paragraph('Relatório de Quarentena', styles['CustomTitle']))
            story.append(Paragraph(
                f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}",
                styles['Footer']
            ))
            story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#2c3e50')))
            story.append(Spacer(1, 0.4 * cm))

            total = quarantine_data.get('total_quarantined', 0)
            story.append(Paragraph('Resumo', styles['SectionHeader']))
            story.append(Paragraph(f"Total de arquivos em quarentena: <b>{total}</b>", styles['BodySmall']))

            by_risk = quarantine_data.get('by_risk', {})
            by_type = quarantine_data.get('by_threat_type', {})

            pie_path = self.chart_generator.generate_risk_pie_chart(by_risk, 'chart_q_risk.png')
            bar_path = self.chart_generator.generate_threat_bar_chart(by_type, 'chart_q_types.png')

            story.append(Paragraph('Distribuição por Risco', styles['SectionHeader']))
            if pie_path and os.path.exists(pie_path):
                story.append(Image(pie_path, width=12 * cm, height=8 * cm))

            story.append(Paragraph('Distribuição por Tipo', styles['SectionHeader']))
            if bar_path and os.path.exists(bar_path):
                story.append(Image(bar_path, width=14 * cm, height=7 * cm))

            # Tabela de quarentena
            qfiles = quarantine_data.get('quarantined_files', [])
            if qfiles:
                story.append(Paragraph('Arquivos em Quarentena', styles['SectionHeader']))
                headers = ['Arquivo Original', 'Risco', 'Tipo', 'Data']
                data = [headers]
                for item in qfiles[:50]:
                    data.append([
                        Path(item.get('original_path', 'N/A')).name,
                        f"{item.get('risk_score', 0):.1%}",
                        item.get('threat_type', 'unknown'),
                        item.get('quarantined_at', 'N/A')[:10],
                    ])
                col_widths = [220, 60, 100, 90]
                table = Table(data, colWidths=col_widths)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f2f2f2')]),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(table)

            doc.build(story)
            print(f"✅ Relatório de Quarentena PDF gerado: {filepath}")
            return str(filepath)

        except Exception as e:
            print(f"❌ Erro ao gerar relatório de quarentena: {e}")
            return None

    # ------------------------------------------------------------------
    # Relatório de Recuperação
    # ------------------------------------------------------------------

    def generate_recovery_report(
        self,
        recovery_data: Dict[str, Any],
        output_file: str = 'recovery_report.pdf'
    ) -> Optional[str]:
        """Gera relatório PDF de recuperação"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
            )
            from reportlab.lib.units import cm
            from reportlab.lib import colors

        except ImportError:
            print("⚠️  reportlab não instalado. Instale com: pip install reportlab")
            return None

        try:
            filepath = self.output_dir / output_file
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm
            )

            styles = self._get_styles()
            story = []

            story.append(Paragraph('🔐 Ransomware Scanner', styles['CustomTitle']))
            story.append(Paragraph('Relatório de Recuperação', styles['CustomTitle']))
            story.append(Paragraph(
                f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}",
                styles['Footer']
            ))
            story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#2c3e50')))
            story.append(Spacer(1, 0.4 * cm))

            total = recovery_data.get('total_recovered', 0)
            story.append(Paragraph('Resumo', styles['SectionHeader']))
            story.append(Paragraph(f"Total de arquivos recuperados: <b>{total}</b>", styles['BodySmall']))

            recovered = recovery_data.get('recovered_files', [])
            if recovered:
                story.append(Paragraph('Arquivos Recuperados', styles['SectionHeader']))
                headers = ['Arquivo Original', 'Método', 'Data']
                data = [headers]
                for item in recovered[:50]:
                    data.append([
                        Path(item.get('original', 'N/A')).name,
                        item.get('method', 'unknown'),
                        item.get('timestamp', 'N/A')[:10],
                    ])
                col_widths = [280, 130, 90]
                table = Table(data, colWidths=col_widths)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f2f2f2')]),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(table)

            # Recomendações de segurança pós-recuperação
            story.append(Spacer(1, 0.4 * cm))
            story.append(Paragraph('Próximos Passos', styles['SectionHeader']))
            for rec in [
                'Verifique a integridade dos arquivos recuperados.',
                'Atualize suas soluções de segurança.',
                'Implemente backups regulares e offsite.',
                'Mantenha o sistema operacional e aplicativos atualizados.',
            ]:
                story.append(Paragraph(f"• {rec}", styles['BodySmall']))

            doc.build(story)
            print(f"✅ Relatório de Recuperação PDF gerado: {filepath}")
            return str(filepath)

        except Exception as e:
            print(f"❌ Erro ao gerar relatório de recuperação: {e}")
            return None


# ============================================================================
# 3. FUNÇÕES AUXILIARES
# ============================================================================

def _fmt_bytes(size: int) -> str:
    """Formata bytes em string legível"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _get_recommendations(by_risk: Dict[str, int]) -> List[str]:
    """Retorna recomendações baseadas nos riscos encontrados"""
    recs = []
    if by_risk.get('critical', 0) > 0:
        recs.append(f"{by_risk['critical']} ameaça(s) CRÍTICA(s) detectada(s). Isole imediatamente os sistemas afetados.")
        recs.append("Execute uma verificação completa dos sistemas da rede.")
    if by_risk.get('high', 0) > 0:
        recs.append(f"{by_risk['high']} ameaça(s) de ALTO risco. Mova os arquivos para quarentena e analise detalhadamente.")
    if by_risk.get('medium', 0) > 0:
        recs.append(f"{by_risk['medium']} ameaça(s) de risco MÉDIO. Monitore esses arquivos continuamente.")
    if not any(by_risk.values()):
        recs.append("Nenhuma ameaça detectada. Mantenha os backups atualizados.")
    recs.append("Mantenha o sistema operacional e os aplicativos atualizados.")
    recs.append("Implemente uma política de backups 3-2-1 (3 cópias, 2 mídias, 1 offsite).")
    recs.append("Habilite autenticação multi-fator em todos os sistemas críticos.")
    return recs


if __name__ == "__main__":
    print("✅ PDF Report Generator loaded successfully!")
