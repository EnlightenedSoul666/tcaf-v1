from core.testcase import TestCase
from core.step_runner import StepRunner
from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.command_step import CommandStep
from steps.screenshot_step import ScreenshotStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep
from steps.analyze_pcap_step import AnalyzePcapStep
from .nmap_parser import parse_open_ports, parse_pcap_for_responses, merge_port_lists
from datetime import datetime
import os
import time


class TC2UDPScan(TestCase):
    def __init__(self):
        super().__init__("TC2_UDP_SCAN", "UDP scan for all ports")

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
        log_file = os.path.join(path, "logs", f"{timestamp}_udp_scan.txt")

        # 1. Start PCAP capture
        StepRunner([PcapStartStep(interface="eth0", filename="udp_scan.pcapng")]).run(context)

        # 2. Cache sudo credentials
        StepRunner([CommandStep("tester", "sudo -v")]).run(context)
        time.sleep(3)

        # 3. Run nmap UDP scan: HYPER-AGGRESSIVE (max speed, don't care about timeouts)
        # We'll capture late responses via PCAP analysis
        nmap_cmd = (
            f"sudo nmap -sU -p- -Pn -n -T5 --min-rate=10000 --max-retries=0 "
            f"--initial-rtt-timeout=50ms {dut_ip} | tee {log_file}"
        )
        StepRunner([CommandStep("tester", "clear")]).run(context)
        StepRunner([CommandStep("tester", nmap_cmd)]).run(context)

        # 4. Wait for nmap to complete (hyper-aggressive, should finish faster)
        print("[*] Waiting for UDP scan to complete...")
        time.sleep(180)  # 3 minutes for aggressive UDP scan

        # 5. Take screenshot of nmap results
        StepRunner([ScreenshotStep(terminal="tester", suffix="udp_scan_results")]).run(context)

        # 6. WAIT LONGER to capture late responses before stopping PCAP
        print("[*] Waiting 60 seconds for late UDP responses to arrive...")
        time.sleep(60)

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
        pcap_ports = parse_pcap_for_responses(pcap_path, dut_ip, proto="udp")

        # Merge: prefer nmap's service names, add any ports only in PCAP
        open_ports = merge_port_lists(nmap_ports, pcap_ports)

        if nmap_ports:
            print(f"[+] nmap found {len(nmap_ports)} UDP ports")
        if pcap_ports:
            print(f"[+] PCAP analysis found {len(pcap_ports)} additional/late responses")
        if open_ports:
            print(f"[+] Total: {len(open_ports)} open UDP ports. Capturing Wireshark evidence...")
        else:
            print("[*] No open UDP ports found (nmap or PCAP).")
            self.status = "PASS"
            return self

        # ---------------------------------------------------------
        # WIRESHARK PROOF FOR EACH OPEN PORT
        # ---------------------------------------------------------
        for port_info in open_ports:
            port = port_info["port"]
            service = port_info["service"]

            # Clear and display header
            StepRunner([CommandStep("tester", "clear")]).run(context)
            header_cmd = f"echo -e '\\n=== UDP Port {port} ({service}) ==='"
            StepRunner([CommandStep("tester", header_cmd)]).run(context)

            # tshark filter: show UDP probe sent + response from DuT
            tshark_filter = (
                f"(ip.dst == {dut_ip} and udp.dstport == {port}) or "
                f"(ip.src == {dut_ip} and udp.srcport == {port})"
            )

            # Run tshark visibly in terminal
            tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
            StepRunner([CommandStep("tester", tshark_cmd)]).run(context)
            time.sleep(1)

            # Take terminal screenshot
            StepRunner([ScreenshotStep(terminal="tester", suffix=f"udp_port_{port}")]).run(context)

            # Wireshark GUI screenshot with full filter
            StepRunner([AnalyzePcapStep(filter_expr=tshark_filter)]).run(context)

            if context.matched_frame:
                StepRunner([WiresharkPacketScreenshotStep(
                    suffix=f"udp_port_{port}",
                    display_filter=tshark_filter
                )]).run(context)
            else:
                print(f"[*] No matching packets for UDP port {port} in pcap.")

        self.status = "PASS"
        return self
