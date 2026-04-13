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
        ("BodyText",       dict(fontName="Helvetica", fontSize=10, leading=14,
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
        if name in styles:
            # Update existing built-in style in-place (e.g. BodyText)
            for k, v in kw.items():
                setattr(styles[name], k, v)
        else:
            styles.add(ParagraphStyle(name, **kw))
    return styles


# ─────────────────────────────────────────────────────────────────────────────
# PAGE TEMPLATE  (header bar + footer bar on every page)
# ─────────────────────────────────────────────────────────────────────────────
class _PageTemplateHelper:
    """Stores the report title so the page template callback can use it."""

    title = "ITSAR COMPLIANCE TEST REPORT"

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
    return [Paragraph(text, styles["BodyText"]), Spacer(1, 3)]


def bullet(text, styles):
    return Paragraph(f"\u2022 {text}", styles["BulletText"])


def label_value(label, value, styles):
    return [
        Paragraph(f"<b>{label}</b>", styles["LabelBold"]),
        Paragraph(str(value), styles["BodyText"]),
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


ICMP_TYPE_NAMES_V4 = {
    0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply",
}
ICMP_TYPE_NAMES_V6 = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
    4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
    133: "Router Solicitation", 134: "Router Advertisement",
    135: "Neighbour Solicitation", 136: "Neighbour Advertisement",
    137: "Redirect",
}


def _classify_port_for_desc(port_num):
    """Look up a port in the IANA/RFC registry for screenshot descriptions."""
    try:
        from clauses.clause_1_9_2.nmap_parser import classify_port
        return classify_port(port_num)
    except Exception:
        return ("unknown", "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", False)


def describe_screenshot(filename):
    """
    Generate a human-readable explanation for a screenshot based on its filename.
    Returns a description string, or None if no meaningful description can be inferred.
    """
    name = os.path.splitext(os.path.basename(filename))[0].lower()
    # Strip timestamp prefix (e.g. "2026_03_11_10-30-00_...")
    parts = name.split("_")
    # Find the meaningful suffix after the timestamp
    suffix = name
    for i, p in enumerate(parts):
        if p in ("tester", "packet", "traceroute", "routing", "respond",
                 "send", "process", "tcp", "udp", "sctp", "ssh", "nmap"):
            suffix = "_".join(parts[i:])
            break

    # ── Routing evidence ──
    if "traceroute" in suffix and "before" in suffix:
        v = "IPv6" if "ipv6" in suffix else "IPv4"
        return (f"Traceroute output captured BEFORE routing configuration ({v}). "
                "Shows the default network path to the target IPs, establishing a baseline "
                "for comparison after routes are configured through the OpenWRT router.")
    if "traceroute" in suffix and "after" in suffix:
        v = "IPv6" if "ipv6" in suffix else "IPv4"
        return (f"Traceroute output captured AFTER route setup ({v}). "
                "Confirms that packets now traverse through the OpenWRT router as the next hop, "
                "verifying the static route configuration was applied successfully.")
    if "routing_table" in suffix:
        v = "IPv6" if "ipv6" in suffix else "IPv4"
        return (f"Routing table output (ip route show) confirming the static routes "
                f"via OpenWRT have been added ({v}). The new entries for the nonsense IP and "
                "auxiliary machine target are visible in the table.")

    # ── ICMP Respond-to tests ──
    if "respond_notpermitted" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        if suffix.startswith("frame_"):
            return (f"Respond-to Not Permitted VIOLATION ({v}): Wireshark capture showing "
                    f"the DuT DID reply to ICMP Type {icmp_type} ({tname}). "
                    "Per ETSI TS 133 117, the DuT must not generate a response to this type. "
                    "The presence of a reply packet indicates NON-COMPLIANCE.")
        return (f"Respond-to Not Permitted verification ({v}): tshark output for "
                f"ICMP Type {icmp_type} ({tname}). "
                "Per ETSI TS 133 117, the DuT must not generate a response to this type. "
                "An empty or absent response confirms compliance; any reply indicates a violation.")
    if "respond" in suffix and "type" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Respond-to test ({v}): tshark analysis showing ICMP Type {icmp_type} "
                f"({tname}) sent to the DuT and the expected reply. "
                "The output shows matched request/response packets from the PCAP capture, "
                "confirming the DuT correctly handles this ICMP type.")

    # ── ICMP Send tests ──
    if "send_notpermitted" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        if suffix.startswith("frame_"):
            return (f"Send Not Permitted VIOLATION ({v}): Wireshark capture showing "
                    f"the DuT DID originate ICMP Type {icmp_type} ({tname}). "
                    "Per ETSI compliance, the DuT must never generate this type. "
                    "The presence of this packet indicates NON-COMPLIANCE.")
        return (f"Send Not Permitted verification ({v}): tshark output for "
                f"ICMP Type {icmp_type} ({tname}). "
                "Per ETSI compliance, the DuT must never generate this type. "
                "An empty result confirms compliance; any packet indicates a violation.")
    if "send" in suffix and "type" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Send test ({v}): tshark output showing the DuT generated ICMP Type "
                f"{icmp_type} ({tname}) in response to the trigger condition. "
                "The captured packets confirm the DuT correctly originates this ICMP type "
                "when the appropriate network condition is provoked.")

    # ── ICMP Redirect tests (logical flow) ──
    if "redirect_before" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Redirect test — BEFORE ({v}): Traceroute to the auxiliary machine showing "
                f"the forced path through the DuT (OpenWRT). A static route was added so "
                f"packets traverse the router, which is required to trigger a Redirect.")
    if "redirect_ping" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Redirect test — PING ({v}): Ping to the auxiliary machine via the forced "
                f"route through OpenWRT. When the router sees the destination is on the same "
                f"interface the packet arrived on, it forwards the packet and sends an ICMP "
                f"Redirect (Type {icmp_type}) back to the sender.")
    if "redirect_after" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Redirect test — AFTER ({v}): Traceroute after the redirect. If the host "
                f"processed the Redirect, the path may now go directly to the auxiliary "
                f"machine. This verifies the Redirect was sent by the router. Per ETSI, "
                f"the DuT itself MUST NOT change its config from received Redirects.")
    if "redirect_pcap" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Redirect test — PCAP analysis ({v}): tshark filter for ICMP Redirect "
                f"(Type {icmp_type}) packets from the DuT. If packets appear, the router "
                f"correctly generated a Redirect. The PCAP confirms whether the DuT sent "
                f"the Redirect to the tester.")
    if "redirect_packet" in suffix or ("packet_frame" in suffix and "redirect" in suffix):
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Redirect test — Wireshark detail ({v}): Packet-level view of the ICMP "
                f"Redirect (Type {icmp_type}) sent by the DuT. The packet shows the "
                f"suggested gateway (direct route to the auxiliary machine) that the "
                f"router is advising the sender to use.")

    # ── ICMP Process tests (RS/RA) ──
    if "process_before" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Process Not Permitted — BEFORE test ({v}): Traceroute to the auxiliary "
                f"machine captured before sending ICMP Type {icmp_type} ({tname}) to the DuT. "
                "This establishes the baseline network path. The DuT must not alter its "
                "routing configuration in response to this ICMP type.")
    if "process_after" in suffix:
        icmp_type = _extract_type(suffix)
        v, tname = _ip_label(suffix, icmp_type)
        return (f"Process Not Permitted — AFTER test ({v}): Traceroute to the auxiliary "
                f"machine captured after sending ICMP Type {icmp_type} ({tname}) to the DuT. "
                "Comparing with the BEFORE traceroute confirms the DuT did NOT process "
                "or act upon this ICMP message — the path remains unchanged.")

    # ── Port scan evidence ──
    if "tcp_scan_results" in suffix:
        return ("Nmap TCP SYN scan (nmap -sS -p- -Pn -n -T5 --max-retries=0 <DuT_IP>): "
                "A TCP SYN probe is sent to every port (1-65535). If the DuT replies with "
                "SYN-ACK, the port is marked 'open'. Only a SYN is sent — the handshake is "
                "never completed (half-open scan), making it stealthy and fast. The results "
                "above list every open TCP port and the service nmap associates with it. "
                "Each port is then classified against the IANA/RFC registry to determine "
                "compliance.")
    if "udp_scan_results" in suffix:
        return ("Nmap UDP scan (nmap -sU -p- -Pn -n -T5 --max-retries=0 <DuT_IP>): "
                "A UDP probe is sent to every port. If no ICMP 'port unreachable' is "
                "returned, the port is considered 'open|filtered'. A genuine application "
                "response marks it 'open'. UDP scanning is slower than TCP because there "
                "is no handshake — the scanner waits for timeouts. Only vendor-documented "
                "UDP services should be found open.")
    if "sctp_scan_results" in suffix:
        return ("Nmap SCTP INIT scan (nmap -sY -p- -Pn -n -T5 --max-retries=0 <DuT_IP>): "
                "An SCTP INIT chunk is sent to every port. If the DuT replies with INIT-ACK, "
                "the port is open. SCTP is a transport protocol used primarily in telecom "
                "signaling (SS7/SIGTRAN/Diameter). Only documented SCTP services should "
                "respond on a CPE.")
    if "tcp_port_" in suffix:
        port = suffix.split("tcp_port_")[-1].split("_")[0]
        svc, url, common = _classify_port_for_desc(int(port) if port.isdigit() else 0)
        verdict = "commonly used for packet transfer" if common else "NOT commonly used — non-compliant"
        return (f"TCP Port {port} — {svc}: Wireshark packet capture showing the TCP "
                f"SYN/SYN-ACK handshake confirming this port is open on the DuT. "
                f"The nmap probe sent a single SYN packet; the DuT replied with SYN-ACK, "
                f"proving the service is listening. Per IANA/RFC this port is assigned to "
                f"{svc} ({url}). Classification: {verdict}.")
    if "udp_port_" in suffix:
        port = suffix.split("udp_port_")[-1].split("_")[0]
        svc, url, common = _classify_port_for_desc(int(port) if port.isdigit() else 0)
        verdict = "commonly used for packet transfer" if common else "NOT commonly used — non-compliant"
        return (f"UDP Port {port} — {svc}: Wireshark packet capture showing the UDP "
                f"request/response confirming this port is open on the DuT. "
                f"Unlike TCP, UDP has no handshake — a response from the DuT "
                f"(rather than ICMP port-unreachable) confirms the service is active. "
                f"Per IANA/RFC this port is assigned to {svc} ({url}). "
                f"Classification: {verdict}.")
    if "sctp_port_" in suffix:
        port = suffix.split("sctp_port_")[-1].split("_")[0]
        svc, url, common = _classify_port_for_desc(int(port) if port.isdigit() else 0)
        verdict = "commonly used for packet transfer" if common else "NOT commonly used — non-compliant"
        return (f"SCTP Port {port} — {svc}: Wireshark packet capture showing the "
                f"SCTP INIT/INIT-ACK exchange confirming this port is open. "
                f"Per IANA/RFC this port is assigned to {svc} ({url}). "
                f"Classification: {verdict}.")

    # ── SSH / crypto evidence ──
    if "ssh" in suffix or "cipher" in suffix or "crypto" in suffix:
        return ("Terminal screenshot showing SSH/TLS cryptographic algorithm enumeration "
                "or handshake capture results. This evidence documents the security "
                "protocols negotiated between the tester and the DuT.")
    if "nmap" in suffix:
        return ("Nmap scan output showing the enumerated services and security configuration "
                "of the DuT. This evidence supports the compliance assessment.")

    # ── Wireshark packet screenshots ──
    if "packet" in suffix or "wireshark" in suffix:
        return ("Wireshark packet capture screenshot showing the relevant network traffic "
                "for this test case. The display filter highlights the specific packets "
                "that evidence the test result.")

    # ── Generic terminal screenshot ──
    if "tester" in suffix:
        return ("Terminal screenshot showing the test execution output on the tester system. "
                "The command output and results are captured as evidence for this test case.")

    return None


def _extract_type(suffix):
    """Extract ICMP type number from a suffix like '...type_8' or '...type_128'."""
    try:
        idx = suffix.index("type_")
        rest = suffix[idx + 5:]
        num = ""
        for ch in rest:
            if ch.isdigit():
                num += ch
            else:
                break
        return int(num) if num else 0
    except (ValueError, IndexError):
        return 0


def _ip_label(suffix, icmp_type):
    """Return (label, type_name) based on whether suffix is IPv4 or IPv6."""
    if "ipv6" in suffix:
        return "IPv6", ICMP_TYPE_NAMES_V6.get(icmp_type, f"Type {icmp_type}")
    return "IPv4", ICMP_TYPE_NAMES_V4.get(icmp_type, f"Type {icmp_type}")


def _enrich_label(ef, label):
    """Enrich a screenshot label with service info for port-specific captures."""
    lower = os.path.basename(ef).lower()
    for proto in ("tcp", "udp", "sctp"):
        tag = f"{proto}_port_"
        if tag in lower:
            port_str = lower.split(tag)[-1].split("_")[0].split(".")[0]
            if port_str.isdigit():
                svc, url, common = _classify_port_for_desc(int(port_str))
                verdict = "PASS" if common else "FAIL"
                return f"{proto.upper()} Port {port_str} — {svc} [{verdict}]"
    return label


def screenshot_block(evidence_files, label, styles):
    """Embed PNG screenshots with explanatory descriptions below each image."""
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
            enriched = _enrich_label(ef, label)
            items += [
                Spacer(1, 2 * mm),
                Paragraph(f"<b>Screenshot Evidence -- {enriched}:</b>", styles["SmallGrey"]),
                img,
            ]

            # Add Observations paragraph below the image
            desc = describe_screenshot(ef)
            if desc:
                items.append(Spacer(1, 2 * mm))
                items.append(Paragraph(
                    "<b>Observations:</b>", styles["LabelBold"]))
                items.append(Paragraph(
                    f"<i>{desc}</i>", styles["BodyText"]))
            items.append(Spacer(1, 3 * mm))

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
    rec = Table([[Paragraph(text, styles["BodyText"])]], colWidths=[W - 40 * mm])
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
    tbl = Table([[Paragraph(text, styles["BodyText"])]], colWidths=[W - 40 * mm])
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
        [Paragraph(k, styles["LabelBold"]), Paragraph(str(v), styles["BodyText"])]
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
        Paragraph(left_label, styles["BodyText"]),
        Paragraph(middle_label, styles["BodyText"]),
        Paragraph(right_label, styles["BodyText"]),
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
    items.append(Paragraph(tc_id, styles["BodyText"]))
    items.append(Spacer(1, 3))

    # b) Description
    items.append(Paragraph("<b>b) Test Case Description:</b>", styles["LabelBold"]))
    items.append(Paragraph(description, styles["BodyText"]))
    items.append(Spacer(1, 3))

    # c) Input Command
    items.append(Paragraph("<b>c) Input Command:</b>", styles["LabelBold"]))
    items.append(output_block(input_cmd or "(automated)", styles))
    items.append(Spacer(1, 3))

    # d) Expected Result
    items.append(Paragraph("<b>d) Expected Result:</b>", styles["LabelBold"]))
    items.append(Paragraph(expected, styles["BodyText"]))
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
    HEADER_TITLE = "ITSAR COMPLIANCE TEST REPORT"

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
