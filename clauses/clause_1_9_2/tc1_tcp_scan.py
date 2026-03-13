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


class TC1TCPScan(TestCase):
    def __init__(self):
        super().__init__("TC1_TCP_SCAN", "TCP SYN scan for all ports")

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
        log_file = os.path.join(path, "logs", f"{timestamp}_tcp_scan.txt")

        # 1. Start PCAP capture (captures both sent SYN probes and DuT responses)
        StepRunner([PcapStartStep(interface="eth0", filename="tcp_scan.pcapng")]).run(context)

        # 2. Cache sudo credentials
        StepRunner([CommandStep("tester", "sudo -v")]).run(context)
        time.sleep(3)

        # 3. Run nmap TCP SYN scan: all ports, no DNS, no ping
        nmap_cmd = f"sudo nmap -sS -p- -Pn -n -T4 {dut_ip} | tee {log_file}"
        StepRunner([CommandStep("tester", "clear")]).run(context)
        StepRunner([CommandStep("tester", nmap_cmd)]).run(context)

        # 4. Wait for nmap to complete (full port scan takes time)
        print("[*] Waiting for TCP SYN scan to complete (this may take a few minutes)...")
        time.sleep(120)  # 2 minutes for full TCP scan with -T4

        # 5. Take screenshot of nmap results
        StepRunner([ScreenshotStep(terminal="tester", suffix="tcp_scan_results")]).run(context)

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
            print("[*] No open TCP ports found.")
            self.status = "PASS"
            return self

        print(f"[+] Found {len(open_ports)} open TCP ports. Capturing Wireshark evidence...")

        # ---------------------------------------------------------
        # WIRESHARK PROOF FOR EACH OPEN PORT
        # ---------------------------------------------------------
        for port_info in open_ports:
            port = port_info["port"]
            service = port_info["service"]

            # Clear and display header
            StepRunner([CommandStep("tester", "clear")]).run(context)
            header_cmd = f"echo -e '\\n=== TCP Port {port} ({service}) ==='"
            StepRunner([CommandStep("tester", header_cmd)]).run(context)

            # tshark filter: show SYN sent + SYN-ACK response pair
            tshark_filter = (
                f"(ip.dst == {dut_ip} and tcp.dstport == {port} and tcp.flags.syn == 1) or "
                f"(ip.src == {dut_ip} and tcp.srcport == {port} and tcp.flags.syn == 1 and tcp.flags.ack == 1)"
            )

            # Run tshark visibly in terminal
            tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
            StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
            time.sleep(1)

            # Take terminal screenshot
            StepRunner([ScreenshotStep(terminal="tester", suffix=f"tcp_port_{port}")]).run(context)

            # Wireshark GUI screenshot with full filter
            StepRunner([AnalyzePcapStep(filter_expr=tshark_filter)]).run(context)

            if context.matched_frame:
                StepRunner([WiresharkPacketScreenshotStep(
                    suffix=f"tcp_port_{port}",
                    display_filter=tshark_filter
                )]).run(context)
            else:
                print(f"[*] No matching packets for port {port} in pcap.")

        self.status = "PASS"
        return self
