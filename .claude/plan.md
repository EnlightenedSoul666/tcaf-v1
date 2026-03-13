# DOCX Report Generator — Implementation Plan

## Goal
Replace the monolithic `DOCXGenerator` in `reporting/pdf_generator.py` with a clause-specific report system that:
- Uses master.py's purple styling (headings, screenshot blocks, tables)
- Generates per-clause reports with clause-specific content
- Pulls screenshots from `output/{clause}/{testcase}/{timestamp}/screenshots/`
- Saves reports to `output/{clause}/reports/{timestamp}_report.docx`
- Creates a new timestamped report each run

## Architecture

### 1. Create `reporting/base_report.py` — Shared formatting helpers
Extract all duplicated styling methods into a base class:
- `add_itsar_heading()`, `add_itsar_subheading()`, `add_bold_paragraph()`
- `add_screenshot_evidence_block()` (from master.py, with purple border + lavender bg)
- `add_grey_horizontal_line()`
- `style_table_header()`, `prevent_table_row_split()`, `keep_with_next()`
- `add_page_number()`, `add_title()`
- `add_data_cell_padding()`

This eliminates the current copy-paste of these methods across `pdf_generator.py` and `clause_1_1_1_report.py`.

### 2. Create clause-specific report classes

Each inherits from `BaseReport` and implements a `generate()` method with clause-specific sections.

**`reporting/clause_reports/clause_1_10_1_report.py`** — ICMP report:
- Section 1: DUT Details (IP, model, serial, firmware)
- Section 2: ITSAR Information (clause 1.10.1, ICMP filtering)
- Section 3: Requirement Description (ICMP type filtering compliance text)
- Section 4: Preconditions (network connectivity, IPv4/IPv6 reachability)
- Section 5: Test Objective (verify DUT filters ICMP types per ITSAR)
- Section 6: Test Scenario (tools: Scapy, tcpdump, Wireshark, tshark)
- Section 7: Test Execution — loops through TC1 (IPv4) and TC2 (IPv6) results, embeds all screenshots from their timestamp folders
- Section 8: Test Observation (dynamic pass/fail text)
- Section 9: Test Case Result Summary table

**`reporting/clause_reports/clause_1_9_2_report.py`** — Port Scanning report:
- Same structure, but content about nmap port scanning
- Section 3: Requirement about open port compliance
- Section 6: Tools: nmap, tcpdump, Wireshark
- Section 7: Test Execution — loops through TC1 (TCP), TC2 (UDP), TC3 (SCTP), embeds screenshots per open port
- Section 9: Result summary for 3 test cases

**`reporting/clause_reports/clause_1_1_1_report.py`** — Update existing:
- Make it inherit from `BaseReport` instead of duplicating styling methods
- Keep existing clause-specific content (SSH authentication)

### 3. Update `reporting/report_factory.py`
Add entries for clause 1.9.2 and 1.10.1.

### 4. Screenshot discovery logic
Each clause report's `generate()` will:
1. Find the latest timestamp folder under `output/{clause}/{testcase}/`
2. Glob all `.png` files from `screenshots/` subfolder
3. Sort by filename and embed each with `add_screenshot_evidence_block()`

### 5. Report output path
- Save to: `output/{clause}/reports/{timestamp}_report.docx`
- Create the `reports/` directory if it doesn't exist
- The timestamp comes from `context.evidence.date_prefix`

### 6. Update `core/engine.py`
Replace the direct `DOCXGenerator` call with `ReportManager().generate(context, results)` which uses the factory.

## Files to Create/Modify

| File | Action |
|------|--------|
| `reporting/base_report.py` | **CREATE** — shared formatting base class |
| `reporting/clause_reports/clause_1_10_1_report.py` | **CREATE** — ICMP clause report |
| `reporting/clause_reports/clause_1_9_2_report.py` | **CREATE** — Port scan clause report |
| `reporting/clause_reports/clause_1_1_1_report.py` | **MODIFY** — inherit from BaseReport |
| `reporting/report_factory.py` | **MODIFY** — add new clause entries |
| `core/engine.py` | **MODIFY** — use ReportManager instead of DOCXGenerator |
| `reporting/pdf_generator.py` | **KEEP** — leave as fallback, no changes needed |
