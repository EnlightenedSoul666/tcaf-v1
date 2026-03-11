from steps.pcap_start_step import PcapStartStep
from steps.pcap_stop_step import PcapStopStep
from steps.command_step import CommandStep  # <--- Updated!
from steps.screenshot_step import ScreenshotStep
from steps.wireshark_packet_screenshot_step import WiresharkPacketScreenshotStep # <--- Updated!
from steps.analyze_pcap_step import AnalyzePcapStep # <--- Updated! (Assuming this is your Tshark background step)
from datetime import datetime
import os
import time


class TC2ICMPIPv6:
    def __init__(self):
        self.name = "TC2_ICMP_IPV6"
        self.status = "PENDING"

    def run(self, context):
        context.current_testcase = self

        print(f"\n--- Running {self.name} ---")
        ipv6_target = input("Enter DuT IPv6 Address: ").strip()
        
        if not ipv6_target:
            print("[-] No IPv6 address provided. Skipping test case.")
            self.status = "SKIPPED"
            return self

        # Setup Logging
        path = context.evidence.testcase_dir(context.clause, self)
        timestamp = datetime.now().strftime("%Y_%m_%d_%H-%M-%S")
        custom_log_file = os.path.join(path, "logs", f"{timestamp}_icmp_ipv6.txt")

        # 1. Start PCAP
        StepRunner([PcapStartStep(interface="eth0", filename="icmp_ipv6.pcapng")]).run(context)
        
        # 2. Fire the IPv6 Payload
        cmd = f"sudo python3 clauses/clause_1_10_1/icmp_forge.py --logfile {custom_log_file} --ipv6 {ipv6_target}"
        StepRunner([CommandStep("clear")]).run(context)
        StepRunner([CommandStep(cmd)]).run(context)
        
        # 3. Stop PCAP
        StepRunner([PcapStopStep()]).run(context)

        # ---------------------------------------------------------
        # THE IPv6 SCREENSHOT LOOP
        # ---------------------------------------------------------
        pcap_path = context.pcap_file
        
        # Map Request Type -> Expected Reply Type
        ipv6_mapping = {
            128: 129, # Echo Request -> Expects Echo Reply (129)
            129: 129, # Echo Reply
            1: 1,     # Dest Unreachable
            2: 2,     # Packet Too Big
            3: 3,     # Time Exceeded
            4: 4,     # Parameter Problem
            133: 134, # Router Solicitation (RS) -> Router Advertisement (RA)
            134: 134, # Router Advertisement
            135: 136, # Neighbor Solicitation (NS) -> Neighbor Advertisement (NA)
            136: 136, # Neighbor Advertisement
            137: 137  # Redirect
        }

        for req_type, expected_reply in ipv6_mapping.items():
            
            # 1. Clear terminal and print header
            StepRunner([CommandStep("clear")]).run(context)
            header_cmd = f"echo -e '\\n=== Auditing IPv6 ICMP Type {req_type} ==='"
            StepRunner([CommandStep(header_cmd)]).run(context)
            
            # 2. Define the exact filter
            tshark_filter = f"(ip.dst == {ipv6_target} and icmp.type == {req_type}) or (ip.src == {ipv6_target} and (icmp.type == {expected_reply} or icmp.type == 3))"
            
            # ---------------------------------------------------------
            # THE TERMINAL PROOF
            # ---------------------------------------------------------
            # 3a. Run Tshark VISIBLY in tmux so we can read it
            tshark_cmd = f"tshark -r {pcap_path} -Y '{tshark_filter}'"
            StepRunner([CommandStep(tshark_cmd)]).run(context)
            time.sleep(1) # Give tmux a second to print the text
            
            # 3b. Take the TERMINAL Screenshot
            StepRunner([ScreenshotStep(terminal="tester", suffix=f"ipv6_type_{req_type}")]).run(context)

            # ---------------------------------------------------------
            # THE WIRESHARK GUI PROOF
            # ---------------------------------------------------------
            # 4a. Run Tshark in the BACKGROUND to grab the frame numbers
            StepRunner([TsharkAnalyzeStep(display_filter=tshark_filter)]).run(context)
            
            # 4b. Use your EXISTING Wireshark step!
            if hasattr(context, 'matched_frames') and context.matched_frames:
                # Tell Wireshark exactly which frame to highlight
                context.packet_frame = context.matched_frames[0] 
                StepRunner([WiresharkScreenshotStep(suffix=f"ipv6_type_{req_type}")]).run(context)
            else:
                # If the router did a "Silent Drop", there are no frames to show in Wireshark!
                print(f"[*] No matching packets found for Type {req_type}. (Silent Drop successful). Skipping Wireshark.")

        self.status = "PASS"
        return self
