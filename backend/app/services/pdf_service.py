from datetime import datetime
import io
from typing import Any, Dict, List, Optional


class PDFDocumentBuilder:
    """
    Self-contained pure-Python PDF 1.4 engine generating enterprise-grade
    CyberShield SOC Executive and Compliance reports with zero external dependencies.
    """

    def __init__(self, title: str, organization_name: str = "Apex CyberDefense"):
        self.title = title
        self.organization_name = organization_name
        self.generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.page_width = 612
        self.page_height = 792
        self.margin = 45

    def _escape_pdf_str(self, text: str) -> str:
        """Sanitizes text for PDF literal strings."""
        if text is None:
            return ""
        return (
            str(text)
            .replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .encode("latin-1", "replace")
            .decode("latin-1")
        )

    def generate_report_pdf(
        self,
        report_type: str,
        executive_summary: str,
        metrics: Dict[str, Any],
        findings_or_records: List[Dict[str, Any]],
        recommendations: List[str],
    ) -> bytes:
        """
        Builds a multi-section executive PDF report.
        """
        stream_cmds: List[str] = []

        # --- Top Header Bar ---
        # Dark primary header background
        stream_cmds.append("q")
        stream_cmds.append("0.05 0.10 0.18 rg")  # #0D1A2D
        stream_cmds.append(f"0 720 {self.page_width} 72 re f")
        stream_cmds.append("0.13 0.60 0.95 rg")  # Cyan accent border
        stream_cmds.append(f"0 718 {self.page_width} 3 re f")
        stream_cmds.append("Q")

        # Header Text
        stream_cmds.append("BT")
        stream_cmds.append("/F1 16 Tf")
        stream_cmds.append("1.0 1.0 1.0 rg")
        stream_cmds.append(f"45 755 Td ({self._escape_pdf_str('CYBERSHIELD SOC INTELLIGENCE REPORT')}) Tj")
        stream_cmds.append("ET")

        stream_cmds.append("BT")
        stream_cmds.append("/F2 9 Tf")
        stream_cmds.append("0.7 0.8 0.9 rg")
        stream_cmds.append(f"45 735 Td ({self._escape_pdf_str(f'Tenant: {self.organization_name}  |  Generated: {self.generated_at}  |  TLP:AMBER+STRICT')}) Tj")
        stream_cmds.append("ET")

        # Report Title
        y = 680
        stream_cmds.append("BT")
        stream_cmds.append("/F1 14 Tf")
        stream_cmds.append("0.1 0.15 0.25 rg")
        stream_cmds.append(f"45 {y} Td ({self._escape_pdf_str(self.title.upper())}) Tj")
        stream_cmds.append("ET")

        # --- Section 1: Executive Summary ---
        y -= 25
        stream_cmds.append("BT")
        stream_cmds.append("/F1 10 Tf")
        stream_cmds.append("0.2 0.4 0.8 rg")
        stream_cmds.append(f"45 {y} Td ({self._escape_pdf_str('1. EXECUTIVE SUMMARY & POSTURE OVERVIEW')}) Tj")
        stream_cmds.append("ET")

        y -= 15
        stream_cmds.append("q")
        stream_cmds.append("0.94 0.96 0.98 rg")
        stream_cmds.append(f"45 {y - 45} 522 55 re f")
        stream_cmds.append("0.80 0.85 0.90 RG 1 w")
        stream_cmds.append(f"45 {y - 45} 522 55 re s")
        stream_cmds.append("Q")

        stream_cmds.append("BT")
        stream_cmds.append("/F2 8.5 Tf")
        stream_cmds.append("0.15 0.20 0.25 rg")
        stream_cmds.append(f"55 {y - 15} Td ({self._escape_pdf_str(executive_summary[:180])}) Tj")
        if len(executive_summary) > 180:
            stream_cmds.append(f"0 -12 Td ({self._escape_pdf_str(executive_summary[180:360])}) Tj")
        stream_cmds.append("ET")

        # --- Section 2: Key Metrics ---
        y -= 80
        stream_cmds.append("BT")
        stream_cmds.append("/F1 10 Tf")
        stream_cmds.append("0.2 0.4 0.8 rg")
        stream_cmds.append(f"45 {y} Td ({self._escape_pdf_str('2. TELEMETRY & POSTURE METRICS')}) Tj")
        stream_cmds.append("ET")

        y -= 12
        card_w = 120
        idx = 0
        for k, v in list(metrics.items())[:4]:
            cx = 45 + idx * (card_w + 14)
            stream_cmds.append("q")
            stream_cmds.append("0.95 0.97 1.0 rg")
            stream_cmds.append(f"{cx} {y - 42} {card_w} 42 re f")
            stream_cmds.append("0.75 0.85 0.95 RG 1 w")
            stream_cmds.append(f"{cx} {y - 42} {card_w} 42 re s")
            stream_cmds.append("Q")

            label = k.replace("_", " ").title()[:18]
            stream_cmds.append("BT")
            stream_cmds.append("/F2 7.5 Tf")
            stream_cmds.append("0.4 0.45 0.55 rg")
            stream_cmds.append(f"{cx + 8} {y - 16} Td ({self._escape_pdf_str(label)}) Tj")
            stream_cmds.append("ET")

            stream_cmds.append("BT")
            stream_cmds.append("/F1 12 Tf")
            stream_cmds.append("0.1 0.2 0.4 rg")
            stream_cmds.append(f"{cx + 8} {y - 34} Td ({self._escape_pdf_str(str(v))}) Tj")
            stream_cmds.append("ET")
            idx += 1

        # --- Section 3: Detailed Telemetry Findings Table ---
        y -= 70
        stream_cmds.append("BT")
        stream_cmds.append("/F1 10 Tf")
        stream_cmds.append("0.2 0.4 0.8 rg")
        stream_cmds.append(f"45 {y} Td ({self._escape_pdf_str('3. DETAILED FINDINGS & CONTROL AUDIT')}) Tj")
        stream_cmds.append("ET")

        y -= 15
        # Table Header
        stream_cmds.append("q")
        stream_cmds.append("0.10 0.20 0.35 rg")
        stream_cmds.append(f"45 {y - 18} 522 18 re f")
        stream_cmds.append("Q")

        stream_cmds.append("BT")
        stream_cmds.append("/F1 8 Tf")
        stream_cmds.append("1.0 1.0 1.0 rg")
        stream_cmds.append(f"52 {y - 12} Td ({self._escape_pdf_str('IDENTIFIER / TITLE')}) Tj")
        stream_cmds.append(f"220 0 Td ({self._escape_pdf_str('SEVERITY / STATUS')}) Tj")
        stream_cmds.append(f"140 0 Td ({self._escape_pdf_str('TARGET / DOMAIN')}) Tj")
        stream_cmds.append("ET")

        # Table Rows
        row_y = y - 18
        for i, item in enumerate(findings_or_records[:7]):
            row_y -= 18
            bg = "0.98 0.98 0.99" if i % 2 == 0 else "0.93 0.95 0.97"
            stream_cmds.append("q")
            stream_cmds.append(f"{bg} rg")
            stream_cmds.append(f"45 {row_y} 522 18 re f")
            stream_cmds.append("Q")

            title_val = item.get("title") or item.get("name") or item.get("control_id") or f"Record #{i+1}"
            sev_val = item.get("severity") or item.get("status") or item.get("device_type") or "Informational"
            target_val = item.get("ip_address") or item.get("domain") or item.get("framework_code") or "Perimeter"

            stream_cmds.append("BT")
            stream_cmds.append("/F2 7.5 Tf")
            stream_cmds.append("0.15 0.2 0.3 rg")
            stream_cmds.append(f"52 {row_y + 5} Td ({self._escape_pdf_str(str(title_val)[:40])}) Tj")
            stream_cmds.append(f"220 0 Td ({self._escape_pdf_str(str(sev_val)[:22])}) Tj")
            stream_cmds.append(f"140 0 Td ({self._escape_pdf_str(str(target_val)[:25])}) Tj")
            stream_cmds.append("ET")

        # --- Section 4: Recommended Remediation Roadmap ---
        y = row_y - 30
        stream_cmds.append("BT")
        stream_cmds.append("/F1 10 Tf")
        stream_cmds.append("0.2 0.4 0.8 rg")
        stream_cmds.append(f"45 {y} Td ({self._escape_pdf_str('4. RECOMMENDED REMEDIATION ACTIONS')}) Tj")
        stream_cmds.append("ET")

        for r_idx, rec in enumerate(recommendations[:3]):
            y -= 16
            stream_cmds.append("BT")
            stream_cmds.append("/F2 8 Tf")
            stream_cmds.append("0.2 0.25 0.35 rg")
            stream_cmds.append(f"55 {y} Td ({self._escape_pdf_str(f'[{r_idx+1}] {rec[:95]}')}) Tj")
            stream_cmds.append("ET")

        # --- Footer ---
        stream_cmds.append("q")
        stream_cmds.append("0.75 0.80 0.85 RG 1 w")
        stream_cmds.append(f"45 40 522 0 m 567 40 l s")
        stream_cmds.append("Q")

        stream_cmds.append("BT")
        stream_cmds.append("/F2 7.5 Tf")
        stream_cmds.append("0.5 0.55 0.6 rg")
        stream_cmds.append(f"45 28 Td ({self._escape_pdf_str('CyberShield Security Platform v2.0  •  ISO 27001 / SOC 2 Type II Confidential')}) Tj")
        stream_cmds.append(f"360 0 Td ({self._escape_pdf_str('Page 1 of 1')}) Tj")
        stream_cmds.append("ET")

        stream_content = "\n".join(stream_cmds).encode("latin-1")
        stream_len = len(stream_content)

        # Assemble PDF Objects
        objects: List[bytes] = []

        # Obj 1: Catalog
        objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # Obj 2: Pages
        objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

        # Obj 3: Page
        objects.append(
            b"3 0 obj\n"
            b"<< /Type /Page\n"
            b"   /Parent 2 0 R\n"
            b"   /MediaBox [0 0 612 792]\n"
            b"   /Contents 4 0 R\n"
            b"   /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >>\n"
            b">>\nendobj\n"
        )

        # Obj 4: Content Stream
        objects.append(
            f"4 0 obj\n<< /Length {stream_len} >>\nstream\n".encode("latin-1")
            + stream_content
            + b"\nendstream\nendobj\n"
        )

        # Obj 5: Font F1 (Helvetica-Bold)
        objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

        # Obj 6: Font F2 (Helvetica)
        objects.append(b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

        # Obj 7: Document Information
        now_pdf = datetime.utcnow().strftime("D:%Y%m%d%H%M%SZ")
        info_str = (
            f"7 0 obj\n<< /Title ({self._escape_pdf_str(self.title)}) "
            f"/Author (CyberShield SOC Engine) "
            f"/Producer (CyberShield SaaS Reporting Engine) "
            f"/CreationDate ({now_pdf}) >>\nendobj\n"
        )
        objects.append(info_str.encode("latin-1"))

        # Calculate exact byte offsets for cross-reference (xref) table
        pdf_header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        xref_offsets = [0]
        current_offset = len(pdf_header)

        for obj in objects:
            xref_offsets.append(current_offset)
            current_offset += len(obj)

        xref_table = [f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("latin-1")]
        for offset in xref_offsets[1:]:
            xref_table.append(f"{offset:010d} 00000 n \n".encode("latin-1"))

        xref_bytes = b"".join(xref_table)
        trailer = (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 7 0 R >>\n"
            f"startxref\n{current_offset}\n%%EOF\n"
        ).encode("latin-1")

        return pdf_header + b"".join(objects) + xref_bytes + trailer
