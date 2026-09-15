"""
tests/test_compliance_and_mitre_reports.py
==========================================
Unit and integration tests for:
- MITRE ATT&CK Matrix coverage computation and SVG heatmap generation
- ComplianceReportService ISO 27001 & NIST CSF posture evaluation
- Publication-ready PDF generation and FastAPI compliance endpoints
"""

import httpx
import pytest

from backend.services.compliance_report_service import compliance_report_service
from backend.services.mitre_coverage_service import mitre_coverage_service
from backend.telemetry_api import app


def test_mitre_coverage_calculation_and_svg():
    """Verify MITRE ATT&CK coverage statistics and SVG vector generation."""
    summary = mitre_coverage_service.get_coverage_summary()
    assert summary["total_tactics"] == 12
    assert summary["total_techniques"] > 20
    assert summary["protected_techniques"] > 0
    assert summary["coverage_pct"] >= 90.0

    svg_data = mitre_coverage_service.render_svg_heatmap()
    assert svg_data.startswith("<svg")
    assert "</svg>" in svg_data
    assert "AEGIS MITRE ATT&amp;CK Matrix Heatmap" in svg_data
    assert "Reconnaissance" in svg_data
    assert "Impact" in svg_data


def test_compliance_posture_and_pdf_generation():
    """Test ISO 27001 and NIST CSF compliance scoring and PDF build."""
    posture = compliance_report_service.get_compliance_posture(
        mttd_ms=3.8, mttr_ms=11.2, containment_rate_pct=99.8
    )
    assert posture["iso_27001"]["overall_score"] >= 90.0
    assert posture["nist_csf"]["status"] == "COMPLIANT"
    assert posture["kpi_metrics"]["mttd_ms"] == 3.8

    pdf_bytes = compliance_report_service.generate_compliance_pdf(
        mttd_ms=3.8, mttr_ms=11.2, containment_rate_pct=99.8
    )
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF")


@pytest.mark.anyio
async def test_compliance_and_mitre_api_endpoints():
    """Test FastAPI REST endpoints for compliance reporting and SVG heatmaps."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. MITRE Matrix
        r_matrix = await client.get("/api/compliance/mitre-matrix")
        assert r_matrix.status_code == 200
        assert r_matrix.json()["coverage_pct"] >= 90.0

        # 2. MITRE SVG
        r_svg = await client.get("/api/compliance/mitre-heatmap.svg")
        assert r_svg.status_code == 200
        assert "image/svg+xml" in r_svg.headers.get("content-type", "")
        assert "<svg" in r_svg.text

        # 3. ISO/NIST JSON
        r_iso = await client.get("/api/compliance/iso27001-nist")
        assert r_iso.status_code == 200
        assert "iso_27001" in r_iso.json()

        # 4. Compliance PDF Export
        r_pdf = await client.get("/api/compliance/export-pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.headers.get("content-type") == "application/pdf"
        assert r_pdf.content.startswith(b"%PDF")
