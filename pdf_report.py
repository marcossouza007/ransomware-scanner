# ============================================================================
# GERADOR DE RELATÓRIOS PDF - v2.0
# ============================================================================

import os
from datetime import datetime
from typing import List, Dict, Optional

import matplotlib.pyplot as plt
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image,
    PageBreak
)

import config
import utils

logger = utils.setup_logger('pdf_report')

# ============================================================================
# GERADOR DE GRÁFICOS
# ============================================================================

class ChartGenerator:
    """Gera gráficos profissionais"""

    @staticmethod
    def create_risk_distribution_chart(threats: List[Dict], output_path: str = None) -> str:
        """Cria gráfico de distribuição de risco"""
        
        if not threats:
            return None

        risk_categories = {'Crítico': 0, 'Alto': 0, 'Médio': 0, 'Baixo': 0}

        for threat in threats:
            score = threat.get('risk_score', 0)
            if score > 0.75:
                risk_categories['Crítico'] += 1
            elif score > 0.45:
                risk_categories['Alto'] += 1
            elif score > 0.25:
                risk_categories['Médio'] += 1
            else:
                risk_categories['Baixo'] += 1

        fig, ax = plt.subplots(figsize=(8, 6))
        colors = ['#FF0000', '#FF8C00', '#FFD700', '#90EE90']
        explode = (0.1, 0.05, 0, 0)

        ax.pie(
            risk_categories.values(),
            labels=risk_categories.keys(),
            autopct='%1.1f%%',
            colors=colors,
            explode=explode,
            startangle=90,
            textprops={'fontsize': 12, 'weight': 'bold'}
        )

        ax.set_title('📊 Distribuição de Risco', fontsize=14, weight='bold', pad=20)

        if output_path is None:
            output_path = os.path.join(config.REPORT_CONFIG['chart_dir'], 'risk_distribution.png')

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        logger.info(f"Gráfico de risco gerado: {output_path}")
        return output_path

    @staticmethod
    def create_threat_type_chart(threats: List[Dict], output_path: str = None) -> str:
        """Cria gráfico de tipos de ameaça"""
        
        if not threats:
            return None

        threat_types = {}
        for threat in threats:
            threat_type = threat.get('threat_type', 'Unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

        fig, ax = plt.subplots(figsize=(10, 6))
        types = list(threat_types.keys())
        counts = list(threat_types.values())

        bars = ax.bar(types, counts, color=['#FF6B6B', '#FF8C42', '#FFD700', '#95E1D3'])

        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height,
                    f'{int(height)}', ha='center', va='bottom', fontweight='bold')

        ax.set_title('📋 Tipos de Ameaça Detectados', fontsize=14, weight='bold', pad=20)
        ax.set_ylabel('Quantidade', fontsize=12, weight='bold')
        ax.set_xlabel('Tipo de Ameaça', fontsize=12, weight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        if output_path is None:
            output_path = os.path.join(config.REPORT_CONFIG['chart_dir'], 'threat_types.png')

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        logger.info(f"Gráfico de tipos gerado: {output_path}")
        return output_path

# ============================================================================
# GERADOR DE RELATÓRIOS PDF
# ============================================================================

class PDFReportGenerator:
    """Gera relatórios profissionais em PDF"""

    COLORS = {
        'primary': HexColor('#1E3A8A'),
        'secondary': HexColor('#64748B'),
        'accent': HexColor('#EF4444')
    }

    def __init__(self, title: str = "Relatório de Segurança"):
        self.title = title
        self.styles = self._create_styles()
        self.chart_gen = ChartGenerator()
        logger.info(f"PDFReportGenerator inicializado: {title}")

    def _create_styles(self):
        """Cria estilos customizados"""
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=self.COLORS['primary'],
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=self.COLORS['secondary'],
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))

        return styles

    def _create_header(self, story: List):
        """Adiciona cabeçalho ao relatório"""
        title = Paragraph(f"🛡️ {self.title}", self.styles['CustomTitle'])
        story.append(title)

        timestamp = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")
        date_para = Paragraph(f"<b>Data do Relatório:</b> {timestamp}", self.styles['Normal'])
        story.append(date_para)
        story.append(Spacer(1, 0.3 * inch))

    def _create_threat_table(self, threats: List[Dict]) -> Table:
        """Cria tabela de ameaças"""
        data = [['#', 'Caminho do Arquivo', 'Risco', 'Tamanho', 'Detectado em']]

        for idx, threat in enumerate(threats, 1):
            risk_score = threat.get('risk_score', 0)
            
            if risk_score > 0.75:
                risk_text = f"🔴 Crítico ({risk_score:.0%})"
            elif risk_score > 0.45:
                risk_text = f"🟠 Alto ({risk_score:.0%})"
            elif risk_score > 0.25:
                risk_text = f"🟡 Médio ({risk_score:.0%})"
            else:
                risk_text = f"🟢 Baixo ({risk_score:.0%})"

            file_path = threat.get('path', 'N/A')
            if len(file_path) > 50:
                file_path = "..." + file_path[-47:]

            size_str = utils.format_size(threat.get('size', 0))
            detected_at = threat.get('timestamp', 'N/A').split('T')[0] if 'T' in threat.get('timestamp', '') else 'N/A'

            data.append([str(idx), file_path, risk_text, size_str, detected_at])

        table = Table(data, colWidths=[0.5*inch, 2.5*inch, 1.2*inch, 1*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F5F5F5')),
            ('TEXTCOLOR', (0, 1), (-1, -1), black),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#F9F9F9')]),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#CCCCCC')),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))

        return table

    def generate_scan_report(self, threats: List[Dict], output_file: str = 'scan_report.pdf') -> bool:
        """Gera relatório de scan"""
        
        output_path = os.path.join(config.REPORT_CONFIG['pdf_dir'], output_file)
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []

        self._create_header(story)

        story.append(Paragraph("📊 Resumo Executivo", self.styles['CustomSubtitle']))
        summary_text = f"""
        <b>Total de Ameaças Detectadas:</b> {len(threats)}<br/>
        <b>Data da Análise:</b> {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}<br/>
        <b>Status:</b> ✅ Scan Concluído
        """
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        if threats:
            story.append(Paragraph("📈 Análises Gráficas", self.styles['CustomSubtitle']))
            
            risk_chart = self.chart_gen.create_risk_distribution_chart(threats)
            if risk_chart and os.path.exists(risk_chart):
                story.append(Image(risk_chart, width=4.5*inch, height=3.5*inch))
                story.append(Spacer(1, 0.2 * inch))
            
            story.append(PageBreak())
            threat_chart = self.chart_gen.create_threat_type_chart(threats)
            if threat_chart and os.path.exists(threat_chart):
                story.append(Image(threat_chart, width=5*inch, height=3*inch))
                story.append(Spacer(1, 0.2 * inch))
            
            story.append(PageBreak())
            story.append(Paragraph("📋 Detalhes de Todas as Ameaças", self.styles['CustomSubtitle']))
            story.append(self._create_threat_table(threats))

        story.append(PageBreak())
        story.append(Paragraph("🔧 Recomendações", self.styles['CustomSubtitle']))
        recommendations = """
        <b>1. Ação Imediata:</b><br/>
        • Coloque em quarentena todos os arquivos marcados como Crítico<br/>
        • Execute descriptografia com chaves conhecidas<br/>
        • Restaure a partir de backups quando disponível<br/>
        <br/>
        
        <b>2. Investigação:</b><br/>
        • Analise logs de acesso do sistema<br/>
        • Identifique ponto de entrada do malware<br/>
        <br/>
        
        <b>3. Prevenção:</b><br/>
        • Atualize antivírus e software de segurança<br/>
        • Implemente backups automatizados<br/>
        """
        story.append(Paragraph(recommendations, self.styles['Normal']))

        doc.build(story)
        logger.info(f"Relatório de scan gerado: {output_path}")
        print(f"✅ Relatório de Scan gerado: {output_path}")
        return True


if __name__ == '__main__':
    print("\n📄 PDF REPORT GENERATOR TEST")
    print("=" * 80)
    pdf_gen = PDFReportGenerator()
    print("✅ PDF Report Generator loaded successfully")
