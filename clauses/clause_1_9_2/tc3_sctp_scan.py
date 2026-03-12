from core.testcase import TestCase
from core.step_runner import StepRunner
from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.command_step import CommandStep
from steps.screenshot_step import ScreenshotStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep
from steps.analyze_pcap_step import AnalyzePcapStep
from .nmap_parser import parse_open_ports
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

        # 2. Cache sudo credentials
        StepRunner([CommandStep("tester", "sudo -v")]).run(context)
        time.sleep(3)

        # 3. Run nmap SCTP INIT scan: all ports, no DNS, no ping
        nmap_cmd = f"sudo nmap -sY -p- -Pn -n -T4 {dut_ip} | tee {log_file}"
        StepRunner([CommandStep("tester", "clear")]).run(context)
        StepRunner([CommandStep("tester", nmap_cmd)]).run(context)

        # 4. Wait for nmap to complete
        print("[*] Waiting for SCTP INIT scan to complete (this may take a few minutes)...")
        time.sleep(180)  # 3 minutes for SCTP scan

        # 5. Take screenshot of nmap results
        StepRunner([ScreenshotStep(terminal="tester", suffix="sctp_scan_results")]).run(context)

        # 6. Stop PCAP
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

        open_ports = parse_open_ports(output)
        pcap_path = context.pcap_file

        if not open_ports:
            print("[*] No open SCTP ports found.")
            self.status = "PASS"
            return self

        print(f"[+] Found {len(open_ports)} open SCTP ports. Capturing Wireshark evidence...")

        # ---------------------------------------------------------
        # WIRESHARK PROOF FOR EACH OPEN PORT
        # ---------------------------------------------------------
        for port_info in open_ports:
            port = port_info["port"]

            # Clear and display header
            StepRunner([CommandStep("tester", "clear")]).run(context)
            header_cmd = f"echo -e '\\n=== SCTP Port {port} ({port_info[\"service\"]}) ==='"
            StepRunner([CommandStep("tester", header_cmd)]).run(context)

            # tshark filter: show SCTP INIT sent + INIT-ACK response pair
            tshark_filter = (
                f"(ip.dst == {dut_ip} and sctp.dstport == {port}) or "
                f"(ip.src == {dut_ip} and sctp.srcport == {port})"
            )

            # Run tshark visibly in terminal
            tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
            StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
            time.sleep(1)

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

        self.status = "PASS"
        return self
