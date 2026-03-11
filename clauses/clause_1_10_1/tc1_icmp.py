from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.command_step import CommandStep  # <--- Updated!
from steps.screenshot_step import ScreenshotStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep # <--- Updated!
from steps.analyze_pcap_step import AnalyzePcapStep # <--- Updated! (Assuming this is your Tshark background step)
from datetime import datetime
import os
import time

class TC1ICMPIPv4:
    def __init__(self):
        self.name = "TC1_ICMP_IPV4"
        self.status = "PENDING"

    def run(self, context):
        context.current_testcase = self

        print(f"\n--- Running {self.name} ---")
        ipv4_target = input("Enter DuT IPv4 Address: ").strip()
        
        if not ipv4_target:
            print("[-] No IPv4 address provided. Skipping test case.")
            self.status = "SKIPPED"
            return self

        # Setup Logging
        path = context.evidence.testcase_dir(context.clause, self)
        timestamp = datetime.now().strftime("%Y_%m_%d_%H-%M-%S")
        custom_log_file = os.path.join(path, "logs", f"{timestamp}_icmp_ipv4.txt")

        # 1. Start PCAP
        StepRunner([PcapStartStep(interface="eth0", filename="icmp_ipv4.pcapng")]).run(context)
        
        # 2. Fire the IPv4 Payload
        cmd = f"sudo python3 clauses/clause_1_10_1/icmp_forge.py --logfile {custom_log_file} --ipv4 {ipv4_target}"
        StepRunner([CommandStep("clear")]).run(context)
        StepRunner([CommandStep(cmd)]).run(context)
        
        # 3. Stop PCAP
        StepRunner([PcapStopStep()]).run(context)

        # ---------------------------------------------------------
        # THE IPv4 SCREENSHOT LOOP
        # ---------------------------------------------------------
        pcap_path = context.pcap_file
        
        # Map Request Type -> Expected Reply Type
        ipv4_mapping = {
            0: 0,   # Echo Reply
            3: 3,   # Dest Unreachable
            5: 5,   # Redirect
            8: 0,   # Echo Request -> Expects Echo Reply (0)
            11: 11, # Time Exceeded
            12: 12, # Parameter Problem
            13: 14, # Timestamp Request -> Expects Timestamp Reply (14)
            14: 14  # Timestamp Reply
        }
        for req_type, expected_reply in ipv4_mapping.items():
            
            # 1. Clear terminal and print header
            StepRunner([CommandStep("clear")]).run(context)
            header_cmd = f"echo -e '\\n=== Auditing IPv4 ICMP Type {req_type} ==='"
            StepRunner([CommandStep(header_cmd)]).run(context)
            
            # 2. Define the exact filter
            tshark_filter = f"(ip.dst == {ipv4_target} and icmp.type == {req_type}) or (ip.src == {ipv4_target} and (icmp.type == {expected_reply} or icmp.type == 3))"
            
            # ---------------------------------------------------------
            # THE TERMINAL PROOF
            # ---------------------------------------------------------
            # 3a. Run Tshark VISIBLY in tmux so we can read it
            tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
            StepRunner([CommandStep(tshark_cmd)]).run(context)
            time.sleep(1) # Give tmux a second to print the text
            
            # 3b. Take the TERMINAL Screenshot
            StepRunner([ScreenshotStep(terminal="tester", suffix=f"ipv4_type_{req_type}")]).run(context)

            # ---------------------------------------------------------
            # THE WIRESHARK GUI PROOF
            # ---------------------------------------------------------
            # 4a. Run Tshark in the BACKGROUND to grab the frame numbers
            StepRunner([TsharkAnalyzeStep(display_filter=tshark_filter)]).run(context)
            
            # 4b. Use your EXISTING Wireshark step!
            if hasattr(context, 'matched_frames') and context.matched_frames:
                # Tell Wireshark exactly which frame to highlight
                context.packet_frame = context.matched_frames[0] 
                StepRunner([WiresharkScreenshotStep(suffix=f"ipv4_type_{req_type}")]).run(context)
            else:
                # If the router did a "Silent Drop", there are no frames to show in Wireshark!
                print(f"[*] No matching packets found for Type {req_type}. (Silent Drop successful). Skipping Wireshark.")
 
        self.status = "PASS"
        return self