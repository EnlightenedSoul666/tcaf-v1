"""
ReportLab PDF Base — shared ITSAR-format styling for all clause reports.

Provides:
  - Blue professional colour palette
  - Custom paragraph styles
  - Page template with header/footer bars
  - Reusable section builders (cover page, tables, screenshot blocks, etc.)

Each clause-specific PDF report subclasses PDFReportBase and overrides
the abstract build_story() method.
"""

import os
import datetime
from abc import ABC, abstractmethod

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Image as RLImage,
)

W, H = A4

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE  (blue professional theme)
# ─────────────────────────────────────────────────────────────────────────────
C_DARK_BLUE  = colors.HexColor("#0D2B45")
C_MID_BLUE   = colors.HexColor("#1A4A72")
C_LIGHT_BLUE = colors.HexColor("#D6E8F7")
C_ACCENT     = colors.HexColor("#0077CC")

C_PASS       = colors.HexColor("#1A7A3C")
C_PASS_BG    = colors.HexColor("#D4EDDA")
C_FAIL       = colors.HexColor("#9B1C1C")
C_FAIL_BG    = colors.HexColor("#FADADD")
C_ERROR      = colors.HexColor("#7B4500")
C_ERROR_BG   = colors.HexColor("#FFF3CD")

C_ROW_ALT    = colors.HexColor("#F0F6FC")
C_WHITE      = colors.white
C_BLACK      = colors.black
C_GREY       = colors.HexColor("#6C757D")
C_GRID       = colors.HexColor("#BDD7EE")
C_TABLE_HDR  = colors.HexColor("#1F3864")


# ─────────────────────────────────────────────────────────────────────────────
# PARAGRAPH STYLES
# ─────────────────────────────────────────────────────────────────────────────
def build_styles():
    styles = getSampleStyleSheet()
    defs = [
        ("ReportTitle",    dict(fontName="Helvetica-Bold", fontSize=20, leading=26,
                                textColor=C_WHITE, alignment=TA_CENTER)),
        ("ReportSubtitle", dict(fontName="Helvetica", fontSize=12, leading=16,
                                textColor=C_LIGHT_BLUE, alignment=TA_CENTER)),
        ("SectionHeading", dict(fontName="Helvetica-Bold", fontSize=13, leading=18,
                                textColor=C_WHITE, spaceAfter=6, spaceBefore=10)),
        ("SubHeading",     dict(fontName="Helvetica-Bold", fontSize=11, leading=15,
                                textColor=C_DARK_BLUE, spaceAfter=4, spaceBefore=8)),
        ("SubSubHeading",  dict(fontName="Helvetica-Bold", fontSize=10, leading=14,
                                textColor=C_MID_BLUE, spaceAfter=3, spaceBefore=6)),
        ("BodyText2",      dict(fontName="Helvetica", fontSize=10, leading=14,
                                textColor=C_BLACK, spaceAfter=4, alignment=TA_JUSTIFY)),
        ("BulletText",     dict(fontName="Helvetica", fontSize=10, leading=14,
                                textColor=C_BLACK, spaceAfter=3, leftIndent=15)),
        ("CodeText",       dict(fontName="Courier", fontSize=8, leading=12,
                                textColor=colors.HexColor("#1a1a1a"), spaceAfter=4)),
        ("SmallGrey",      dict(fontName="Helvetica", fontSize=8, leading=11,
                                textColor=C_GREY)),
        ("TableHdr",       dict(fontName="Helvetica-Bold", fontSize=9, leading=12,
                                textColor=C_WHITE, alignment=TA_CENTER)),
        ("TableCell",      dict(fontName="Helvetica", fontSize=9, leading=12,
                                textColor=C_BLACK)),
        ("VerdictPASS",    dict(fontName="Helvetica-Bold", fontSize=10,
                                textColor=C_PASS, alignment=TA_CENTER)),
        ("VerdictFAIL",    dict(fontName="Helvetica-Bold", fontSize=10,
                                textColor=C_FAIL, alignment=TA_CENTER)),
        ("LabelBold",      dict(fontName="Helvetica-Bold", fontSize=10, leading=14,
                                textColor=C_BLACK, spaceAfter=2)),
    ]
    for name, kw in defs:
        styles.add(ParagraphStyle(name, **kw))
    return styles


# ─────────────────────────────────────────────────────────────────────────────
# PAGE TEMPLATE  (header bar + footer bar on every page)
# ─────────────────────────────────────────────────────────────────────────────
class _PageTemplateHelper:
    """Stores the report title so the page template callback can use it."""

    title = "TCAF COMPLIANCE TEST REPORT  |  ITSAR FORMAT"

    @classmethod
    def draw(cls, canvas, doc):
        canvas.saveState()

        # ── Header bar ───────────────────────────
        canvas.setFillColor(C_DARK_BLUE)
        canvas.rect(0, H - 18 * mm, W, 18 * mm, fill=1, stroke=0)

        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(C_WHITE)
        canvas.drawString(20 * mm, H - 11 * mm, cls.title)

        canvas.setFont("Helvetica", 8)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        canvas.drawRightString(W - 20 * mm, H - 11 * mm, ts)

        # Accent line
        canvas.setStrokeColor(C_ACCENT)
        canvas.setLineWidth(1.5)
        canvas.line(0, H - 18 * mm, W, H - 18 * mm)

        # ── Footer bar ───────────────────────────
        canvas.setFillColor(C_DARK_BLUE)
        canvas.rect(0, 0, W, 10 * mm, fill=1, stroke=0)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#AAAAAA"))
        canvas.drawString(20 * mm, 3 * mm, "CONFIDENTIAL - Security Test Documentation")

        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawRightString(W - 20 * mm, 3 * mm, f"Page {canvas.getPageNumber()}")

        canvas.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# REUSABLE ELEMENT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def section_header(text, styles):
    """Blue banner with white section heading text."""
    tbl = Table(
        [[Paragraph(text, styles["SectionHeading"])]],
        colWidths=[W - 40 * mm],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_MID_BLUE),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return [Spacer(1, 6), tbl, Spacer(1, 5)]


def sub_heading(text, styles):
    return [Paragraph(text, styles["SubHeading"])]


def sub_sub_heading(text, styles):
    return [Paragraph(text, styles["SubSubHeading"])]


def body(text, styles):
    return [Paragraph(text, styles["BodyText2"]), Spacer(1, 3)]


def bullet(text, styles):
    return Paragraph(f"\u2022 {text}", styles["BulletText"])


def label_value(label, value, styles):
    return [
        Paragraph(f"<b>{label}</b>", styles["LabelBold"]),
        Paragraph(str(value), styles["BodyText2"]),
        Spacer(1, 4),
    ]


def output_block(text, styles):
    """Grey code/output box with Courier font."""
    tbl = Table(
        [[Paragraph(str(text)[:1200] or "(no output)", styles["CodeText"])]],
        colWidths=[W - 40 * mm],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#F4F4F4")),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return tbl


def verdict_color(verdict):
    """Return (text_color, bg_color) for a verdict string."""
    v = verdict.upper()
    if v == "PASS":
        return C_PASS, C_PASS_BG
    if v == "FAIL":
        return C_FAIL, C_FAIL_BG
    return C_ERROR, C_ERROR_BG


def tc_header_bar(tc_id, tc_name, verdict, styles):
    """Colored test-case header row (ID | Name | Verdict)."""
    vc, vb = verdict_color(verdict)
    tbl = Table([[
        Paragraph(f"<b>{tc_id}</b>", styles["SubHeading"]),
        Paragraph(tc_name, styles["TableCell"]),
        Paragraph(
            f"<b>{verdict}</b>",
            ParagraphStyle("vh", fontName="Helvetica-Bold", fontSize=10,
                           textColor=vc, alignment=TA_CENTER),
        ),
    ]], colWidths=[28 * mm, W - 40 * mm - 28 * mm - 24 * mm, 24 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), vb),
        ("BOX",           (0, 0), (-1, -1), 0.8, vc),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return tbl


def verdict_banner(verdict, styles):
    """Full-width colored verdict bar."""
    vc, vb = verdict_color(verdict)
    vt = Table([[Paragraph(
        f"<b>VERDICT: {verdict}</b>",
        ParagraphStyle("VB", fontName="Helvetica-Bold", fontSize=11,
                       textColor=vc, alignment=TA_CENTER),
    )]], colWidths=[W - 40 * mm])
    vt.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), vb),
        ("BOX",           (0, 0), (-1, -1), 1, vc),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return vt


def screenshot_block(evidence_files, label, styles):
    """Embed PNG screenshots scaled to fit within page margins."""
    items = []
    for ef in (evidence_files or []):
        if not ef or not str(ef).endswith(".png") or not os.path.exists(ef):
            continue
        try:
            from PIL import Image as PILImage
            with PILImage.open(ef) as pi:
                iw, ih = pi.size
            max_w = 155 * mm
            max_h = 90 * mm
            scale = min(max_w / iw, max_h / ih)
            img = RLImage(ef, width=iw * scale, height=ih * scale)
            img.hAlign = "LEFT"
            items += [
                Spacer(1, 2 * mm),
                Paragraph(f"<b>Screenshot Evidence -- {label}:</b>", styles["SmallGrey"]),
                img,
                Spacer(1, 2 * mm),
            ]
        except Exception as ex:
            items.append(Paragraph(f"[Screenshot error: {ex}]", styles["SmallGrey"]))
    return items


def results_table(results, styles, tc_id_key="tc_id", tc_name_key="tc_name",
                  verdict_key="verdict", remarks_key="remarks"):
    """
    Generic results summary table.

    Works with both dict-based results and object-based results.
    """
    hdr_style = ParagraphStyle(
        "TH2", fontName="Helvetica-Bold", fontSize=9,
        textColor=C_WHITE, alignment=TA_CENTER,
    )
    data = [[
        Paragraph("SL. No",        hdr_style),
        Paragraph("TEST CASE NAME", hdr_style),
        Paragraph("PASS/FAIL",      hdr_style),
        Paragraph("Remarks",        hdr_style),
    ]]

    for i, r in enumerate(results, 1):
        # Support both dict and object access
        if isinstance(r, dict):
            name    = r.get(tc_name_key, r.get(tc_id_key, f"TC{i}"))
            v       = r.get(verdict_key, "N/A")
            remarks = r.get(remarks_key, "")
        else:
            name    = getattr(r, "name", f"TC{i}")
            v       = getattr(r, "status", "N/A")
            remarks = getattr(r, "remarks", "")

        vc, _ = verdict_color(v)
        data.append([
            Paragraph(str(i), styles["TableCell"]),
            Paragraph(str(name)[:60], styles["TableCell"]),
            Paragraph(
                f"<b>{v}</b>",
                ParagraphStyle("vv", fontName="Helvetica-Bold", fontSize=9,
                               textColor=vc, alignment=TA_CENTER),
            ),
            Paragraph(str(remarks)[:80], styles["TableCell"]),
        ])

    tbl = Table(data, colWidths=[15 * mm, 85 * mm, 25 * mm, W - 40 * mm - 125 * mm],
                repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_TABLE_HDR),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_GRID),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
    ]))
    return tbl


def stats_row(total, passed, failed, overall, styles):
    """Summary statistics row (Total | PASS count | FAIL count | Overall)."""
    col_w = (W - 40 * mm) / 4
    hdr_s = ParagraphStyle(
        "ths", fontName="Helvetica-Bold", fontSize=9,
        textColor=C_WHITE, alignment=TA_CENTER,
    )
    ov_c, _ = verdict_color(overall)
    tbl = Table([
        [Paragraph("Total", hdr_s), Paragraph("PASS", hdr_s),
         Paragraph("FAIL", hdr_s),  Paragraph("Overall", hdr_s)],
        [Paragraph(str(total), styles["TableCell"]),
         Paragraph(str(passed), ParagraphStyle(
             "ps", fontName="Helvetica-Bold", fontSize=10,
             textColor=C_PASS, alignment=TA_CENTER)),
         Paragraph(str(failed), ParagraphStyle(
             "fs", fontName="Helvetica-Bold", fontSize=10,
             textColor=C_FAIL, alignment=TA_CENTER)),
         Paragraph(overall, ParagraphStyle(
             "os2", fontName="Helvetica-Bold", fontSize=10,
             textColor=ov_c, alignment=TA_CENTER))],
    ], colWidths=[col_w] * 4)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_TABLE_HDR),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_GRID),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
    ]))
    return tbl


def compliance_table(checks, styles):
    """
    Compliance analysis mapping: requirement <-> test cases <-> result.

    checks = [("Requirement text", "TC-IDs", "PASS/FAIL"), ...]
    """
    hdr_s = ParagraphStyle(
        "cth", fontName="Helvetica-Bold", fontSize=9,
        textColor=C_WHITE, alignment=TA_CENTER,
    )
    data = [[
        Paragraph("<b>Clause Requirement</b>", hdr_s),
        Paragraph("<b>Test Case(s)</b>", hdr_s),
        Paragraph("<b>Result</b>", hdr_s),
    ]]
    for req_txt, tcs, comp in checks:
        cc, _ = verdict_color(comp)
        data.append([
            Paragraph(req_txt, styles["TableCell"]),
            Paragraph(tcs, styles["TableCell"]),
            Paragraph(
                f"<b>{comp}</b>",
                ParagraphStyle("cc", fontName="Helvetica-Bold", fontSize=9,
                               textColor=cc, alignment=TA_CENTER),
            ),
        ])
    tbl = Table(data, colWidths=[90 * mm, 55 * mm, 30 * mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_TABLE_HDR),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_GRID),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
    ]))
    return tbl


def recommendation_box(text, styles):
    """Blue info-box for recommendations."""
    rec = Table([[Paragraph(text, styles["BodyText2"])]], colWidths=[W - 40 * mm])
    rec.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#EBF5FB")),
        ("BOX",           (0, 0), (-1, -1), 1, C_ACCENT),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return rec


def info_box(text, styles):
    """Light-blue requirement info box."""
    tbl = Table([[Paragraph(text, styles["BodyText2"])]], colWidths=[W - 40 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT_BLUE),
        ("BOX",           (0, 0), (-1, -1), 1, C_ACCENT),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return tbl


def metadata_table(rows_data, styles):
    """Two-column metadata table (label | value) with alternating rows."""
    meta_data = [
        [Paragraph(k, styles["LabelBold"]), Paragraph(str(v), styles["BodyText2"])]
        for k, v in rows_data
    ]
    mt = Table(meta_data, colWidths=[55 * mm, W - 40 * mm - 55 * mm])
    mt.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_GRID),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
    ]))
    return mt


def testbed_diagram(left_label, middle_label, right_label, styles):
    """Simple three-column test bed diagram."""
    tb = Table([[
        Paragraph(left_label, styles["BodyText2"]),
        Paragraph(middle_label, styles["BodyText2"]),
        Paragraph(right_label, styles["BodyText2"]),
    ]], colWidths=[55 * mm, 65 * mm, 55 * mm])
    tb.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), C_LIGHT_BLUE),
        ("BACKGROUND", (2, 0), (2, 0), C_PASS_BG),
        ("BACKGROUND", (1, 0), (1, 0), C_WHITE),
        ("BOX",        (0, 0), (-1, -1), 0.5, C_GRID),
        ("INNERGRID",  (0, 0), (-1, -1), 0.5, C_GRID),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return tb


# ─────────────────────────────────────────────────────────────────────────────
# COVER PAGE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_cover_page(clause_title, clause_subtitle, meta_rows,
                     overall, styles):
    """
    Returns a list of story elements for a professional cover page.

    meta_rows = [("Key", "Value"), ...]
    """
    story = [Spacer(1, 25 * mm)]

    for txt, sty, bg in [
        ("SECURITY TEST REPORT",  "ReportTitle",    C_DARK_BLUE),
        (clause_title,            "ReportSubtitle", C_MID_BLUE),
        (clause_subtitle,         "ReportSubtitle", C_MID_BLUE),
    ]:
        t = Table([[Paragraph(txt, styles[sty])]], colWidths=[W - 40 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    story.append(Spacer(1, 10 * mm))
    story.append(metadata_table(meta_rows, styles))
    story.append(Spacer(1, 8 * mm))

    ov_c, ov_b = verdict_color(overall)
    ov_tbl = Table([[Paragraph(
        f"<b>OVERALL RESULT: {overall}</b>",
        ParagraphStyle("OV", fontName="Helvetica-Bold", fontSize=16,
                       textColor=ov_c, alignment=TA_CENTER),
    )]], colWidths=[W - 40 * mm])
    ov_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), ov_b),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("BOX",           (0, 0), (-1, -1), 1.5, ov_c),
    ]))
    story.append(ov_tbl)
    story.append(PageBreak())

    return story


# ─────────────────────────────────────────────────────────────────────────────
# PER-TEST-CASE DETAIL BUILDER  (7-field breakdown: a-g)
# ─────────────────────────────────────────────────────────────────────────────

def build_tc_detail(tc_num, tc_id, tc_name, description, input_cmd,
                    expected, actual_status, output_text, verdict,
                    evidence_files, styles):
    """
    Full 7-field test case detail block (a through g) with screenshots.

    Returns a list of story elements.
    """
    items = []

    # a) Test Case Name
    items.append(Paragraph("<b>a) Test Case Name:</b>", styles["LabelBold"]))
    items.append(Paragraph(tc_id, styles["BodyText2"]))
    items.append(Spacer(1, 3))

    # b) Description
    items.append(Paragraph("<b>b) Test Case Description:</b>", styles["LabelBold"]))
    items.append(Paragraph(description, styles["BodyText2"]))
    items.append(Spacer(1, 3))

    # c) Input Command
    items.append(Paragraph("<b>c) Input Command:</b>", styles["LabelBold"]))
    items.append(output_block(input_cmd or "(automated)", styles))
    items.append(Spacer(1, 3))

    # d) Expected Result
    items.append(Paragraph("<b>d) Expected Result:</b>", styles["LabelBold"]))
    items.append(Paragraph(expected, styles["BodyText2"]))
    items.append(Spacer(1, 3))

    # e) Actual Result
    items.append(Paragraph("<b>e) Actual Result:</b>", styles["LabelBold"]))
    vc, _ = verdict_color(verdict)
    items.append(Paragraph(
        actual_status or verdict,
        ParagraphStyle("ar", fontName="Helvetica-Bold", fontSize=10, textColor=vc),
    ))
    items.append(Spacer(1, 3))

    # f) Command Output
    items.append(Paragraph("<b>f) Command Output:</b>", styles["LabelBold"]))
    items.append(output_block(output_text or "(see screenshots)", styles))
    items.append(Spacer(1, 3))

    # g) Verdict bar
    items.append(verdict_banner(verdict, styles))

    # Screenshots
    items += screenshot_block(evidence_files, tc_id, styles)
    items.append(Spacer(1, 6))

    # KeepTogether for the first 6 items to avoid page-break in the middle
    story = []
    story.append(KeepTogether(items[:6]))
    story += items[6:]
    story.append(Spacer(1, 4 * mm))

    return story


# ─────────────────────────────────────────────────────────────────────────────
# FIND SCREENSHOTS IN OUTPUT DIRECTORY
# ─────────────────────────────────────────────────────────────────────────────

def find_screenshots_for_tc(context, clause_id, testcase_name):
    """
    Search the evidence output tree for screenshots belonging to a test case.
    Returns a sorted list of PNG file paths.
    """
    import glob as _glob

    base = os.path.join(context.evidence.run_dir, str(clause_id), testcase_name)
    if not os.path.isdir(base):
        return []

    # Try current run timestamp first
    ts_dir = os.path.join(base, context.evidence.date_prefix, "screenshots")
    if os.path.isdir(ts_dir):
        files = sorted(_glob.glob(os.path.join(ts_dir, "*.png")))
        if files:
            return files

    # Fallback: most recent timestamp folder
    try:
        timestamps = sorted(os.listdir(base), reverse=True)
    except OSError:
        return []
    for ts in timestamps:
        ss_dir = os.path.join(base, ts, "screenshots")
        if os.path.isdir(ss_dir):
            files = sorted(_glob.glob(os.path.join(ss_dir, "*.png")))
            if files:
                return files
    return []


# ─────────────────────────────────────────────────────────────────────────────
# BASE CLASS FOR ALL PDF REPORTS
# ─────────────────────────────────────────────────────────────────────────────

class PDFReportBase(ABC):
    """
    Abstract base class for ReportLab PDF reports.

    Subclasses must:
      - Set CLAUSE_ID  (e.g., "1.1.1")
      - Set HEADER_TITLE (page header text)
      - Implement build_story(context, results, styles) -> list
    """

    CLAUSE_ID    = "0.0.0"
    HEADER_TITLE = "TCAF COMPLIANCE TEST REPORT  |  ITSAR FORMAT"

    def __init__(self, context, results):
        self.context = context
        self.results = results

    @abstractmethod
    def build_story(self, context, results, styles):
        """Return a list of ReportLab flowable elements."""
        ...

    def generate(self, context=None, results=None):
        """
        Build and save the PDF.  Returns the output file path.
        """
        ctx = context or self.context
        res = results or self.results

        # Output path: output/{clause}/reports/{timestamp}_report.pdf
        reports_dir = os.path.join(
            ctx.evidence.run_dir, str(self.CLAUSE_ID), "reports",
        )
        os.makedirs(reports_dir, exist_ok=True)
        filename = f"{ctx.evidence.date_prefix}_report.pdf"
        output_path = os.path.join(reports_dir, filename)

        styles = build_styles()
        _PageTemplateHelper.title = self.HEADER_TITLE

        story = self.build_story(ctx, res, styles)

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=22 * mm, bottomMargin=14 * mm,
            title=self.HEADER_TITLE,
        )
        doc.build(story,
                  onFirstPage=_PageTemplateHelper.draw,
                  onLaterPages=_PageTemplateHelper.draw)

        return output_path

    # ── Convenience helpers available to subclasses ───────────────────────

    def compute_overall(self, results):
        """Compute overall PASS/FAIL from results list."""
        for r in results:
            status = r.get("verdict", "FAIL") if isinstance(r, dict) else getattr(r, "status", "FAIL")
            if status.upper() != "PASS":
                return "FAIL"
        return "PASS"

    def count_results(self, results):
        """Return (total, passed, failed, errors)."""
        total = len(results)
        passed = failed = errors = 0
        for r in results:
            v = r.get("verdict", "N/A") if isinstance(r, dict) else getattr(r, "status", "N/A")
            v = v.upper()
            if v == "PASS":
                passed += 1
            elif v == "FAIL":
                failed += 1
            else:
                errors += 1
        return total, passed, failed, errors
