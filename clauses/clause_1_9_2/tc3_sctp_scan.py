from core.testcase import TestCase
from core.step_runner import StepRunner
from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.command_step import CommandStep
from steps.screenshot_step import ScreenshotStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep
from steps.analyze_pcap_step import AnalyzePcapStep
from .nmap_parser import parse_open_ports, parse_pcap_for_responses, merge_port_lists, classify_open_ports
from datetime import datetime
import os
import time


class TC3SCTPScan(TestCase):
    def __init__(self):
        super().__init__("TC3_SCTP_SCAN", "SCTP INIT scan for all ports")

    def run(self, context):
        context.current_testcase = self

        print(f"\n--- Running {self.name} ---")

        dut_ip = context.dut_ip
        if not dut_ip:
            print("[-] No DuT IP address provided. Skipping test case.")
            self.status = "SKIPPED"
            return self

        # Setup evidence directory
        path = context.evidence.testcase_dir(context.clause, self)
        timestamp = datetime.now().strftime("%Y_%m_%d_%H-%M-%S")
        log_file = os.path.join(path, "logs", f"{timestamp}_sctp_scan.txt")

        # 1. Start PCAP capture
        StepRunner([PcapStartStep(interface="eth0", filename="sctp_scan.pcapng")]).run(context)

        # 2. Cache sudo credentials (provide password via stdin to avoid tmux prompt)
        if context.sudo_password:
            sudo_cmd = f"echo '{context.sudo_password}' | sudo -S -v"
        else:
            sudo_cmd = "sudo -v"
        StepRunner([CommandStep("tester", sudo_cmd)]).run(context)
        time.sleep(3)

        # 3. Run nmap SCTP INIT scan: SINGLE PROBE PER PORT (no retries)
        nmap_cmd = (
            f"sudo nmap -sY -p- -Pn -n -T5 --max-retries=0 "
            f"--initial-rtt-timeout=100ms --script-timeout=1ms {dut_ip} | tee {log_file}"
        )
        StepRunner([CommandStep("tester", "clear")]).run(context)
        StepRunner([CommandStep("tester", nmap_cmd)]).run(context)

        # 4. Wait for nmap to complete (hyper-aggressive, faster)
        print("[*] Waiting for SCTP INIT scan to complete...")
        time.sleep(120)  # 2 minutes for aggressive SCTP scan

        # 5. Take screenshot of nmap results
        StepRunner([ScreenshotStep(terminal="tester", suffix="sctp_scan_results")]).run(context)

        # 6. WAIT for late responses before stopping PCAP
        print("[*] Waiting 15 seconds for late SCTP responses to arrive...")
        time.sleep(15)

        # 7. Stop PCAP
        StepRunner([PcapStopStep()]).run(context)

        # 7. Capture nmap output to parse open ports
        output = context.terminal_manager.capture_output("tester")

        # Save raw output
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            with open(log_file, "w") as f:
                f.write(output)
        except Exception:
            pass

        # Parse both nmap output AND PCAP
        nmap_ports = parse_open_ports(output)
        pcap_path = context.pcap_file
        pcap_ports = parse_pcap_for_responses(pcap_path, dut_ip, proto="sctp")

        # Merge: prefer nmap's service names, add any ports only in PCAP
        open_ports = merge_port_lists(nmap_ports, pcap_ports)

        if nmap_ports:
            print(f"[+] nmap found {len(nmap_ports)} SCTP ports")
        if pcap_ports:
            print(f"[+] PCAP analysis found {len(pcap_ports)} additional/late responses")
        if open_ports:
            print(f"[+] Total: {len(open_ports)} open SCTP ports. Classifying & capturing evidence...")
        else:
            print("[*] No open SCTP ports found (nmap or PCAP).")
            self.status = "PASS"
            return self

        # Classify every port against the IANA/RFC registry
        open_ports, has_non_standard = classify_open_ports(open_ports)

        if has_non_standard:
            non_std = [p for p in open_ports if not p["is_common"]]
            print(f"[!] {len(non_std)} non-standard port(s) found — overall FAIL")
            for p in non_std:
                print(f"    Port {p['port']}: {p['rfc_service']} (RFC: {p['rfc_url']})")
        else:
            print("[+] All discovered ports are commonly used for packet transfer.")

        # ---------------------------------------------------------
        # WIRESHARK PROOF FOR EACH OPEN PORT
        # ---------------------------------------------------------
        for port_info in open_ports:
            port = port_info["port"]
            service = port_info["service"]

            # Clear and display header
            StepRunner([CommandStep("tester", "clear")]).run(context)
            header_cmd = f"echo -e '\\n=== SCTP Port {port} ({service}) ==='"
            StepRunner([CommandStep("tester", header_cmd)]).run(context)

            # tshark filter: show SCTP INIT sent + INIT-ACK response pair (exclude ICMP rejects)
            tshark_filter = (
                f"(ip.dst == {dut_ip} and sctp.dstport == {port}) or "
                f"(ip.src == {dut_ip} and sctp.srcport == {port} and not icmp)"
            )

            # Run tshark visibly in terminal
            tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
            StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
            time.sleep(3)  # Wait for tshark to process large PCAP and display results

            # Take terminal screenshot
            StepRunner([ScreenshotStep(terminal="tester", suffix=f"sctp_port_{port}")]).run(context)

            # Wireshark GUI screenshot with full filter
            StepRunner([AnalyzePcapStep(filter_expr=tshark_filter)]).run(context)

            if context.matched_frame:
                StepRunner([WiresharkPacketScreenshotStep(
                    suffix=f"sctp_port_{port}",
                    display_filter=tshark_filter
                )]).run(context)
            else:
                print(f"[*] No matching packets for SCTP port {port} in pcap.")

            # Record per-port sub_result for reporting
            self.sub_results.append({
                "port": port,
                "proto": "sctp",
                "nmap_service": port_info.get("service", ""),
                "rfc_service": port_info.get("rfc_service", "unknown"),
                "rfc_url": port_info.get("rfc_url", ""),
                "is_common": port_info.get("is_common", False),
                "status": port_info.get("port_status", "FAIL"),
            })

        # Overall verdict: FAIL if any port is not commonly used
        self.status = "FAIL" if has_non_standard else "PASS"
        return self
