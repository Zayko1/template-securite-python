import os
import tempfile

import pygal
from fpdf import FPDF

from tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport d'Analyse Reseau - TP1 IDS/IPS"
        self.summary = summary
        self.array: list[tuple] = []
        self.graph: list[tuple] = []   # sorted (proto, count) for PDF drawing
        self._svg_path: str = ""

    def concat_report(self) -> str:
        """
        Concat all data in report (text fallback)
        """
        lines = [self.title, "", self.summary, ""]
        if self.array:
            lines.append("Protocole          | Paquets")
            lines.append("-" * 30)
            for proto, count in sorted(self.array, key=lambda x: x[1], reverse=True):
                lines.append(f"{proto:<18} | {count}")
        return "\n".join(lines)

    def save(self, filename: str) -> None:
        """
        Save report as a PDF file
        :param filename:
        :return:
        """
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # ── Title ──────────────────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, self.title, new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(4)

        # ── Summary ────────────────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Resume de l'analyse", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for line in self.summary.split("\n"):
            pdf.multi_cell(0, 6, line if line else " ", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # ── Legitimacy section ─────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 12)
        if self.capture.alerts:
            pdf.set_text_color(180, 0, 0)
            pdf.cell(0, 8, f"Legitimite du trafic - {len(self.capture.alerts)} alerte(s)", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", size=10)
            for alert in self.capture.alerts:
                pdf.set_fill_color(255, 220, 220)
                pdf.multi_cell(
                    0, 6,
                    f"[{alert['type']}] {alert['detail']}\n"
                    f"  Protocole : {alert['protocol']}  |  IP : {alert['src_ip']}  |  MAC : {alert['src_mac']}",
                    fill=True,
                    new_x="LMARGIN", new_y="NEXT",
                )
                pdf.ln(2)
        else:
            pdf.set_text_color(0, 140, 0)
            pdf.cell(0, 8, "Legitimite du trafic - Tout va bien, aucune menace detectee.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        # ── Protocol table ─────────────────────────────────────────────────
        if self.array:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Tableau des protocoles captures", new_x="LMARGIN", new_y="NEXT")
            self._draw_table(pdf)
            pdf.ln(6)

        # ── Bar chart ──────────────────────────────────────────────────────
        if self.graph:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Graphique - Distribution des protocoles", new_x="LMARGIN", new_y="NEXT")
            self._draw_bar_chart(pdf)

        # Reference the standalone SVG
        if self._svg_path and os.path.exists(self._svg_path):
            pdf.set_font("Helvetica", "I", 9)
            pdf.ln(2)
            pdf.cell(0, 6, f"Graphique interactif disponible : {self._svg_path}", new_x="LMARGIN", new_y="NEXT")

        pdf.output(filename)

    # ── Private helpers ────────────────────────────────────────────────────

    def _draw_table(self, pdf: FPDF) -> None:
        col_w = [95, 95]
        headers = ["Protocole", "Nombre de paquets"]

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(70, 130, 180)
        pdf.set_text_color(255, 255, 255)
        for i, h in enumerate(headers):
            pdf.cell(col_w[i], 8, h, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=10)
        alt = False
        for proto, count in sorted(self.array, key=lambda x: x[1], reverse=True):
            pdf.set_fill_color(220, 235, 250) if alt else pdf.set_fill_color(255, 255, 255)
            pdf.cell(col_w[0], 7, proto, border=1, fill=True, align="C")
            pdf.cell(col_w[1], 7, str(count), border=1, fill=True, align="C")
            pdf.ln()
            alt = not alt

    def _draw_bar_chart(self, pdf: FPDF) -> None:
        """Draw a bar chart using fpdf2 drawing primitives"""
        sorted_data = self.graph
        if not sorted_data:
            return

        max_count = max(c for _, c in sorted_data)
        n = len(sorted_data)

        chart_left = 25
        chart_top = pdf.get_y() + 5
        chart_w = 160
        chart_h = 65
        bar_slot = chart_w / n
        bar_w = bar_slot * 0.6
        bar_offset = bar_slot * 0.2

        colors = [
            (70, 130, 180), (255, 165, 0), (60, 179, 113),
            (220, 20, 60), (147, 112, 219), (64, 224, 208),
        ]

        for i, (proto, count) in enumerate(sorted_data):
            bar_h = (count / max_count) * chart_h
            x = chart_left + i * bar_slot + bar_offset
            y = chart_top + chart_h - bar_h

            pdf.set_fill_color(*colors[i % len(colors)])
            pdf.rect(x, y, bar_w, bar_h, style="F")

            # Count label above bar
            pdf.set_font("Helvetica", size=7)
            pdf.set_xy(x - 2, y - 5)
            pdf.cell(bar_w + 4, 4, str(count), align="C")

            # Protocol label below axis
            pdf.set_xy(x - 2, chart_top + chart_h + 2)
            pdf.cell(bar_w + 4, 4, proto[:7], align="C")

        # Axes
        pdf.set_draw_color(80, 80, 80)
        pdf.line(chart_left, chart_top, chart_left, chart_top + chart_h)
        pdf.line(chart_left, chart_top + chart_h, chart_left + chart_w, chart_top + chart_h)

        pdf.set_y(chart_top + chart_h + 10)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            self._generate_graph()
        elif param == "array":
            self.array = list(self.capture.protocol_counts.items())

    def _generate_graph(self) -> None:
        """Generate bar chart data and export SVG with pygal"""
        if not self.capture.protocol_counts:
            return

        sorted_data = sorted(
            self.capture.protocol_counts.items(), key=lambda x: x[1], reverse=True
        )
        self.graph = sorted_data

        # Export interactive SVG with pygal
        chart = pygal.Bar(
            title="Distribution des protocoles réseau",
            print_values=True,
        )
        for proto, count in sorted_data:
            chart.add(proto, count)

        tmp = tempfile.NamedTemporaryFile(suffix=".svg", delete=False, prefix="tp1_chart_")
        chart.render_to_file(tmp.name)
        self._svg_path = tmp.name
