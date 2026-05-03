# ============================================================================
# GERADOR DE RELATÓRIOS PDF - RANSOMWARE SCANNER v2.0
# ============================================================================

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from config import REPORTS_DIR, CHARTS_DIR, RISK_LEVELS
from utils import logger, print_success, print_error, print_warning

# ============================================================================
# 1. GERAÇÃO DE GRÁFICOS
# ============================================================================

def generate_risk_distribution_chart(
    by_risk: Dict[str, int],
    output_path: str
) -> Optional[str]:
    """Gera gráfico de pizza com distribuição de risco"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        labels = []
        sizes = []
        colors = []
        color_map = {
            'critical': '#FF4444',
            'high': '#FF8C00',
            'medium': '#FFD700',
            'low': '#90EE90',
        }

        for level, count in by_risk.items():
            if count > 0:
                labels.append(f"{level.capitalize()} ({count})")
                sizes.append(count)
                colors.append(color_map.get(level, '#AAAAAA'))

        if not sizes:
            return None

        fig, ax = plt.subplots(figsize=(8, 6))
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            pctdistance=0.85,
        )

        for autotext in autotexts:
            autotext.set_fontsize(10)
            autotext.set_fontweight('bold')

        ax.set_title('Distribuição de Risco', fontsize=16, fontweight='bold', pad=20)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
        plt.close(fig)

        logger.info(f"Risk distribution chart saved: {output_path}")
        return output_path

    except ImportError:
        logger.warning("matplotlib not installed — skipping chart generation")
        return None
    except Exception as e:
        logger.error(f"Error generating risk chart: {e}")
        return None


def generate_threat_types_chart(
    by_type: Dict[str, int],
    output_path: str
) -> Optional[str]:
    """Gera gráfico de barras com tipos de ameaça"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        if not by_type:
            return None

        labels = list(by_type.keys())
        values = list(by_type.values())
        bar_colors = [
            '#FF4444', '#FF8C00', '#FFD700', '#90EE90',
            '#4169E1', '#9370DB', '#20B2AA', '#DC143C',
        ]

        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.bar(
            labels,
            values,
            color=bar_colors[:len(labels)],
            edgecolor='white',
            linewidth=1.5,
        )

        for bar, value in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.05,
                str(value),
                ha='center',
                va='bottom',
                fontsize=11,
                fontweight='bold',
            )

        ax.set_title('Tipos de Ameaça Detectados', fontsize=16, fontweight='bold', pad=15)
        ax.set_xlabel('Tipo de Ameaça', fontsize=12)
        ax.set_ylabel('Quantidade', fontsize=12)
        ax.set_ylim(0, max(values) * 1.2 if values else 1)
        ax.grid(axis='y', alpha=0.3)
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
        plt.close(fig)

        logger.info(f"Threat types chart saved: {output_path}")
        return output_path

    except ImportError:
        logger.warning("matplotlib not installed — skipping chart generation")
        return None
    except Exception as e:
        logger.error(f"Error generating threat types chart: {e}")
        return None


def generate_timeline_chart(
    threats: List[Dict],
    output_path: str
) -> Optional[str]:
    """Gera gráfico de linha com timeline de detecções"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from collections import Counter

        if not threats:
            return None

        # Agrupa por hora
        hour_counts: Counter = Counter()
        for threat in threats:
            try:
                ts = datetime.fromisoformat(threat.get('timestamp', ''))
                hour_key = ts.strftime('%H:%M')
                hour_counts[hour_key] += 1
            except Exception:
                pass

        if not hour_counts:
            return None

        sorted_hours = sorted(hour_counts.keys())
        counts = [hour_counts[h] for h in sorted_hours]

        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(sorted_hours, counts, color='#FF4444', linewidth=2.5, marker='o', markersize=6)
        ax.fill_between(sorted_hours, counts, alpha=0.15, color='#FF4444')
        ax.set_title('Timeline de Detecções', fontsize=16, fontweight='bold', pad=15)
        ax.set_xlabel('Horário', fontsize=12)
        ax.set_ylabel('Ameaças Detectadas', fontsize=12)
        ax.grid(alpha=0.3)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
        plt.close(fig)

        logger.info(f"Timeline chart saved: {output_path}")
        return output_path

    except ImportError:
        logger.warning("matplotlib not installed — skipping chart generation")
        return None
    except Exception as e:
        logger.error(f"Error generating timeline chart: {e}")
        return None


# ============================================================================
# 2. GERADOR DE PDF
# ============================================================================

class PDFReportGenerator:
    """Gera relatórios profissionais em PDF"""

    def __init__(self, output_dir: str = str(REPORTS_DIR)):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.charts_dir = Path(str(CHARTS_DIR))
        self.charts_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"PDF report generator initialized: {output_dir}")

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _get_reportlab(self):
        """Importa reportlab ou lança ImportError com mensagem amigável"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch, cm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table,
                TableStyle, Image, PageBreak, HRFlowable,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            return {
                'colors': colors,
                'A4': A4,
                'getSampleStyleSheet': getSampleStyleSheet,
                'ParagraphStyle': ParagraphStyle,
                'inch': inch,
                'cm': cm,
                'SimpleDocTemplate': SimpleDocTemplate,
                'Paragraph': Paragraph,
                'Spacer': Spacer,
                'Table': Table,
                'TableStyle': TableStyle,
                'Image': Image,
                'PageBreak': PageBreak,
                'HRFlowable': HRFlowable,
                'TA_CENTER': TA_CENTER,
                'TA_LEFT': TA_LEFT,
                'TA_RIGHT': TA_RIGHT,
            }
        except ImportError:
            raise ImportError(
                "reportlab não instalado. Instale com: pip install reportlab"
            )

    def _build_styles(self, rl: dict) -> dict:
        """Cria estilos do documento"""
        base = rl['getSampleStyleSheet']()
        styles = {
            'title': rl['ParagraphStyle'](
                'CustomTitle',
                parent=base['Title'],
                fontSize=24,
                textColor=rl['colors'].HexColor('#1a1a2e'),
                spaceAfter=6,
                alignment=rl['TA_CENTER'],
                fontName='Helvetica-Bold',
            ),
            'subtitle': rl['ParagraphStyle'](
                'CustomSubtitle',
                parent=base['Normal'],
                fontSize=12,
                textColor=rl['colors'].HexColor('#666666'),
                spaceAfter=12,
                alignment=rl['TA_CENTER'],
            ),
            'heading1': rl['ParagraphStyle'](
                'CustomHeading1',
                parent=base['Heading1'],
                fontSize=16,
                textColor=rl['colors'].HexColor('#16213e'),
                spaceBefore=16,
                spaceAfter=8,
                fontName='Helvetica-Bold',
            ),
            'heading2': rl['ParagraphStyle'](
                'CustomHeading2',
                parent=base['Heading2'],
                fontSize=13,
                textColor=rl['colors'].HexColor('#0f3460'),
                spaceBefore=10,
                spaceAfter=6,
                fontName='Helvetica-Bold',
            ),
            'body': rl['ParagraphStyle'](
                'CustomBody',
                parent=base['Normal'],
                fontSize=10,
                textColor=rl['colors'].HexColor('#333333'),
                spaceAfter=6,
                leading=14,
            ),
            'table_header': rl['ParagraphStyle'](
                'TableHeader',
                parent=base['Normal'],
                fontSize=9,
                textColor=rl['colors'].white,
                fontName='Helvetica-Bold',
                alignment=rl['TA_CENTER'],
            ),
            'table_cell': rl['ParagraphStyle'](
                'TableCell',
                parent=base['Normal'],
                fontSize=9,
                textColor=rl['colors'].HexColor('#333333'),
            ),
            'risk_critical': rl['ParagraphStyle'](
                'RiskCritical',
                parent=base['Normal'],
                fontSize=9,
                textColor=rl['colors'].HexColor('#CC0000'),
                fontName='Helvetica-Bold',
                alignment=rl['TA_CENTER'],
            ),
            'risk_high': rl['ParagraphStyle'](
                'RiskHigh',
                parent=base['Normal'],
                fontSize=9,
                textColor=rl['colors'].HexColor('#CC5500'),
                fontName='Helvetica-Bold',
                alignment=rl['TA_CENTER'],
            ),
            'risk_medium': rl['ParagraphStyle'](
                'RiskMedium',
                parent=base['Normal'],
                fontSize=9,
                textColor=rl['colors'].HexColor('#AA8800'),
                fontName='Helvetica-Bold',
                alignment=rl['TA_CENTER'],
            ),
            'risk_low': rl['ParagraphStyle'](
                'RiskLow',
                parent=base['Normal'],
                fontSize=9,
                textColor=rl['colors'].HexColor('#226622'),
                fontName='Helvetica-Bold',
                alignment=rl['TA_CENTER'],
            ),
        }
        return styles

    def _risk_style_name(self, score: float) -> str:
        if score > 0.75:
            return 'risk_critical'
        elif score > 0.45:
            return 'risk_high'
        elif score > 0.25:
            return 'risk_medium'
        return 'risk_low'

    def _risk_label(self, score: float) -> str:
        if score > 0.75:
            return 'CRÍTICO'
        elif score > 0.45:
            return 'ALTO'
        elif score > 0.25:
            return 'MÉDIO'
        return 'BAIXO'

    def _header_table_style(self, rl: dict) -> list:
        return [
            ('BACKGROUND', (0, 0), (-1, 0), rl['colors'].HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), rl['colors'].white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, rl['colors'].HexColor('#CCCCCC')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [rl['colors'].white, rl['colors'].HexColor('#F5F5F5')]),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]

    def _add_chart_if_exists(self, elements: list, chart_path: str, width_cm: float, rl: dict):
        """Adiciona imagem ao documento se existir"""
        if chart_path and os.path.isfile(chart_path):
            try:
                from PIL import Image as PILImage
                with PILImage.open(chart_path) as pil_img:
                    orig_w, orig_h = pil_img.size

                target_w = width_cm * rl['cm']
                target_h = target_w * orig_h / orig_w

                img = rl['Image'](chart_path, width=target_w, height=target_h)
                elements.append(img)
                elements.append(rl['Spacer'](1, 0.3 * rl['cm']))
            except Exception as e:
                logger.warning(f"Could not embed chart {chart_path}: {e}")

    # ------------------------------------------------------------------
    # 2.1 Relatório de Scan
    # ------------------------------------------------------------------

    def generate_scan_report(
        self,
        scan_data: Dict,
        output_filename: str = None
    ) -> Optional[str]:
        """Gera relatório PDF de scan de ransomware"""
        try:
            rl = self._get_reportlab()
        except ImportError as e:
            print_warning(str(e))
            return None

        if output_filename is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f"scan_report_{ts}.pdf"

        output_path = str(self.output_dir / output_filename)
        styles = self._build_styles(rl)
        elements = []

        doc = rl['SimpleDocTemplate'](
            output_path,
            pagesize=rl['A4'],
            rightMargin=2 * rl['cm'],
            leftMargin=2 * rl['cm'],
            topMargin=2.5 * rl['cm'],
            bottomMargin=2 * rl['cm'],
        )

        # ------ CAPA ------
        elements.append(rl['Spacer'](1, 1 * rl['cm']))
        elements.append(rl['Paragraph']('🛡️ RANSOMWARE SCANNER', styles['title']))
        elements.append(rl['Paragraph']('Relatório de Detecção de Ameaças', styles['subtitle']))
        elements.append(rl['Paragraph'](
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}",
            styles['subtitle'],
        ))
        elements.append(rl['HRFlowable'](
            width='100%', thickness=2,
            color=rl['colors'].HexColor('#16213e'), spaceAfter=20,
        ))

        # ------ RESUMO EXECUTIVO ------
        elements.append(rl['Paragraph']('📋 Resumo Executivo', styles['heading1']))

        threats = scan_data.get('threats', [])
        total = scan_data.get('total_threats', len(threats))
        duration = scan_data.get('scan_duration', 0)

        by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        by_type: Dict[str, int] = {}
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

        summary_data = [
            ['Métrica', 'Valor'],
            ['Total de Ameaças Detectadas', str(total)],
            ['Ameaças Críticas 🔴', str(by_risk['critical'])],
            ['Ameaças Altas 🟠', str(by_risk['high'])],
            ['Ameaças Médias 🟡', str(by_risk['medium'])],
            ['Ameaças Baixas 🟢', str(by_risk['low'])],
            ['Duração do Scan', f"{duration:.1f}s"],
            ['Timestamp', scan_data.get('timestamp', 'N/A')],
        ]

        summary_table = rl['Table'](summary_data, colWidths=[10 * rl['cm'], 7 * rl['cm']])
        summary_table.setStyle(rl['TableStyle'](self._header_table_style(rl)))
        elements.append(summary_table)
        elements.append(rl['Spacer'](1, 0.5 * rl['cm']))

        # ------ GRÁFICOS ------
        if threats:
            elements.append(rl['Paragraph']('📊 Análise Visual', styles['heading1']))

            chart_risk = str(self.charts_dir / 'chart_risk_distribution.png')
            generate_risk_distribution_chart(by_risk, chart_risk)
            self._add_chart_if_exists(elements, chart_risk, 14, rl)

            chart_types = str(self.charts_dir / 'chart_threat_types.png')
            generate_threat_types_chart(by_type, chart_types)
            self._add_chart_if_exists(elements, chart_types, 16, rl)

            chart_timeline = str(self.charts_dir / 'chart_timeline.png')
            generate_timeline_chart(threats, chart_timeline)
            self._add_chart_if_exists(elements, chart_timeline, 16, rl)

        # ------ DETALHES DAS AMEAÇAS ------
        if threats:
            elements.append(rl['PageBreak']())
            elements.append(rl['Paragraph']('🚨 Detalhes das Ameaças', styles['heading1']))

            detail_data = [['#', 'Arquivo', 'Tipo', 'Risco', 'Score', 'Extensão']]
            for idx, threat in enumerate(threats, 1):
                score = threat.get('risk_score', 0)
                detail_data.append([
                    str(idx),
                    os.path.basename(threat.get('path', 'N/A')),
                    threat.get('threat_type', 'unknown'),
                    self._risk_label(score),
                    f"{score:.2%}",
                    threat.get('extension', 'N/A'),
                ])

            col_widths = [1 * rl['cm'], 6 * rl['cm'], 3 * rl['cm'],
                          2.5 * rl['cm'], 2 * rl['cm'], 2.5 * rl['cm']]
            detail_table = rl['Table'](detail_data, colWidths=col_widths, repeatRows=1)
            detail_table.setStyle(rl['TableStyle'](self._header_table_style(rl)))
            elements.append(detail_table)
            elements.append(rl['Spacer'](1, 0.5 * rl['cm']))

        # ------ RECOMENDAÇÕES ------
        elements.append(rl['Paragraph']('💡 Recomendações de Segurança', styles['heading1']))
        recommendations = [
            '1. Isole imediatamente os sistemas afetados da rede.',
            '2. Coloque todos os arquivos críticos em quarentena.',
            '3. Não pague o resgate — busque ferramentas de recuperação gratuitas.',
            '4. Restaure arquivos a partir de backups verificados.',
            '5. Atualize todos os sistemas operacionais e softwares.',
            '6. Revise e fortaleça as políticas de acesso e permissões.',
            '7. Implemente monitoramento contínuo contra reinfecção.',
            '8. Registre o incidente e notifique autoridades competentes.',
        ]
        for rec in recommendations:
            elements.append(rl['Paragraph'](rec, styles['body']))

        try:
            doc.build(elements)
            logger.info(f"Scan PDF report generated: {output_path}")
            print_success(f"Relatório PDF de Scan gerado: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error building scan PDF: {e}")
            print_error(f"Erro ao gerar PDF: {e}")
            return None

    # ------------------------------------------------------------------
    # 2.2 Relatório de Quarentena
    # ------------------------------------------------------------------

    def generate_quarantine_report(
        self,
        quarantine_data: Dict,
        output_filename: str = None
    ) -> Optional[str]:
        """Gera relatório PDF de quarentena"""
        try:
            rl = self._get_reportlab()
        except ImportError as e:
            print_warning(str(e))
            return None

        if output_filename is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f"quarantine_report_{ts}.pdf"

        output_path = str(self.output_dir / output_filename)
        styles = self._build_styles(rl)
        elements = []

        doc = rl['SimpleDocTemplate'](
            output_path,
            pagesize=rl['A4'],
            rightMargin=2 * rl['cm'],
            leftMargin=2 * rl['cm'],
            topMargin=2.5 * rl['cm'],
            bottomMargin=2 * rl['cm'],
        )

        # ------ CAPA ------
        elements.append(rl['Spacer'](1, 1 * rl['cm']))
        elements.append(rl['Paragraph']('🔒 QUARENTENA', styles['title']))
        elements.append(rl['Paragraph']('Relatório de Arquivos em Quarentena', styles['subtitle']))
        elements.append(rl['Paragraph'](
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}",
            styles['subtitle'],
        ))
        elements.append(rl['HRFlowable'](
            width='100%', thickness=2,
            color=rl['colors'].HexColor('#16213e'), spaceAfter=20,
        ))

        # ------ RESUMO ------
        elements.append(rl['Paragraph']('📋 Resumo', styles['heading1']))

        by_risk = quarantine_data.get('by_risk', {})
        by_type = quarantine_data.get('by_threat_type', {})
        total = quarantine_data.get('total_quarantined', 0)

        summary_data = [
            ['Métrica', 'Valor'],
            ['Total em Quarentena', str(total)],
            ['Críticos', str(by_risk.get('critical', 0))],
            ['Altos', str(by_risk.get('high', 0))],
            ['Médios', str(by_risk.get('medium', 0))],
            ['Baixos', str(by_risk.get('low', 0))],
            ['Timestamp', quarantine_data.get('timestamp', 'N/A')],
        ]

        t = rl['Table'](summary_data, colWidths=[10 * rl['cm'], 7 * rl['cm']])
        t.setStyle(rl['TableStyle'](self._header_table_style(rl)))
        elements.append(t)
        elements.append(rl['Spacer'](1, 0.5 * rl['cm']))

        # ------ GRÁFICOS ------
        elements.append(rl['Paragraph']('📊 Análise Visual', styles['heading1']))

        chart_risk = str(self.charts_dir / 'chart_quarantine_risk.png')
        generate_risk_distribution_chart(by_risk, chart_risk)
        self._add_chart_if_exists(elements, chart_risk, 14, rl)

        chart_types = str(self.charts_dir / 'chart_quarantine_types.png')
        generate_threat_types_chart(by_type, chart_types)
        self._add_chart_if_exists(elements, chart_types, 16, rl)

        # ------ LISTA DE ARQUIVOS ------
        quarantined_files = quarantine_data.get('quarantined_files', [])
        if quarantined_files:
            elements.append(rl['PageBreak']())
            elements.append(rl['Paragraph']('📁 Arquivos em Quarentena', styles['heading1']))

            rows = [['#', 'Arquivo Original', 'Tipo', 'Risco', 'Score', 'Data']]
            for idx, item in enumerate(quarantined_files, 1):
                score = item.get('risk_score', 0)
                rows.append([
                    str(idx),
                    os.path.basename(item.get('original_path', 'N/A')),
                    item.get('threat_type', 'unknown'),
                    self._risk_label(score),
                    f"{score:.2%}",
                    item.get('quarantined_at', 'N/A')[:10],
                ])

            col_widths = [1 * rl['cm'], 6 * rl['cm'], 3 * rl['cm'],
                          2.5 * rl['cm'], 2 * rl['cm'], 2.5 * rl['cm']]
            tbl = rl['Table'](rows, colWidths=col_widths, repeatRows=1)
            tbl.setStyle(rl['TableStyle'](self._header_table_style(rl)))
            elements.append(tbl)

        try:
            doc.build(elements)
            logger.info(f"Quarantine PDF report generated: {output_path}")
            print_success(f"Relatório PDF de Quarentena gerado: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error building quarantine PDF: {e}")
            print_error(f"Erro ao gerar PDF: {e}")
            return None

    # ------------------------------------------------------------------
    # 2.3 Relatório de Recuperação
    # ------------------------------------------------------------------

    def generate_recovery_report(
        self,
        recovery_data: Dict,
        output_filename: str = None
    ) -> Optional[str]:
        """Gera relatório PDF de recuperação"""
        try:
            rl = self._get_reportlab()
        except ImportError as e:
            print_warning(str(e))
            return None

        if output_filename is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f"recovery_report_{ts}.pdf"

        output_path = str(self.output_dir / output_filename)
        styles = self._build_styles(rl)
        elements = []

        doc = rl['SimpleDocTemplate'](
            output_path,
            pagesize=rl['A4'],
            rightMargin=2 * rl['cm'],
            leftMargin=2 * rl['cm'],
            topMargin=2.5 * rl['cm'],
            bottomMargin=2 * rl['cm'],
        )

        # ------ CAPA ------
        elements.append(rl['Spacer'](1, 1 * rl['cm']))
        elements.append(rl['Paragraph']('🔐 RECUPERAÇÃO', styles['title']))
        elements.append(rl['Paragraph']('Relatório de Recuperação de Arquivos', styles['subtitle']))
        elements.append(rl['Paragraph'](
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}",
            styles['subtitle'],
        ))
        elements.append(rl['HRFlowable'](
            width='100%', thickness=2,
            color=rl['colors'].HexColor('#16213e'), spaceAfter=20,
        ))

        # ------ RESUMO ------
        elements.append(rl['Paragraph']('📋 Resumo', styles['heading1']))

        recovered_files = recovery_data.get('recovered_files', [])
        total = recovery_data.get('total_recovered', len(recovered_files))

        methods: Dict[str, int] = {}
        for item in recovered_files:
            m = item.get('method', 'unknown')
            methods[m] = methods.get(m, 0) + 1

        summary_data = [
            ['Métrica', 'Valor'],
            ['Total de Arquivos Recuperados', str(total)],
            ['Timestamp', recovery_data.get('timestamp', 'N/A')],
        ]
        for method, count in methods.items():
            summary_data.append([f'Método: {method}', str(count)])

        t = rl['Table'](summary_data, colWidths=[10 * rl['cm'], 7 * rl['cm']])
        t.setStyle(rl['TableStyle'](self._header_table_style(rl)))
        elements.append(t)
        elements.append(rl['Spacer'](1, 0.5 * rl['cm']))

        # ------ GRÁFICO POR MÉTODO ------
        if methods:
            elements.append(rl['Paragraph']('📊 Distribuição por Método', styles['heading1']))
            chart_path = str(self.charts_dir / 'chart_recovery_methods.png')
            generate_threat_types_chart(methods, chart_path)
            self._add_chart_if_exists(elements, chart_path, 14, rl)

        # ------ DETALHES ------
        if recovered_files:
            elements.append(rl['Paragraph']('📄 Detalhes da Recuperação', styles['heading1']))

            rows = [['#', 'Arquivo Original', 'Arquivo Recuperado', 'Método', 'Data']]
            for idx, item in enumerate(recovered_files, 1):
                rows.append([
                    str(idx),
                    os.path.basename(item.get('original', 'N/A')),
                    os.path.basename(item.get('decrypted', item.get('recovered', 'N/A'))),
                    item.get('method', 'unknown'),
                    item.get('timestamp', 'N/A')[:10],
                ])

            col_widths = [1 * rl['cm'], 5 * rl['cm'], 5 * rl['cm'],
                          3 * rl['cm'], 3 * rl['cm']]
            tbl = rl['Table'](rows, colWidths=col_widths, repeatRows=1)
            tbl.setStyle(rl['TableStyle'](self._header_table_style(rl)))
            elements.append(tbl)

        # ------ RECOMENDAÇÕES ------
        elements.append(rl['Spacer'](1, 0.5 * rl['cm']))
        elements.append(rl['Paragraph']('💡 Próximos Passos', styles['heading1']))
        next_steps = [
            '1. Verifique a integridade dos arquivos recuperados.',
            '2. Execute scan completo após a recuperação.',
            '3. Atualize os backups para versões limpas.',
            '4. Monitore o sistema por 30 dias após o incidente.',
            '5. Implemente solução de backup automático e testado.',
        ]
        for step in next_steps:
            elements.append(rl['Paragraph'](step, styles['body']))

        try:
            doc.build(elements)
            logger.info(f"Recovery PDF report generated: {output_path}")
            print_success(f"Relatório PDF de Recuperação gerado: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error building recovery PDF: {e}")
            print_error(f"Erro ao gerar PDF: {e}")
            return None


if __name__ == "__main__":
    print("✅ PDF Report Generator loaded successfully!")
