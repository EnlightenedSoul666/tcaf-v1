import subprocess
import time
from core.step import Step
from utils.logger import logger


class WiresharkPacketScreenshotStep(Step):

    def __init__(self, suffix="", display_filter=None):
        super().__init__("Capture Wireshark Packet Screenshot")
        self.suffix = f"_{suffix}" if suffix else ""
        self.display_filter = display_filter

    def execute(self, context):
        pcap = context.pcap_file

        # Use provided display filter, or fall back to single frame
        if self.display_filter:
            ws_filter = self.display_filter
        elif context.matched_frame:
            ws_filter = f"frame.number == {context.matched_frame}"
        else:
            logger.warning("No filter or matched frame -- skipping Wireshark screenshot")
            return None

        clause = context.clause
        testcase = context.current_testcase
        screenshot_dir = context.evidence.screenshot_path(clause, testcase)

        base_name = f"packet_frame{self.suffix}.png"
        timestamped_name = context.evidence.get_timestamped_filename(base_name)
        screenshot_file = f"{screenshot_dir}/{timestamped_name}"

        logger.info(f"Opening Wireshark with filter: {ws_filter}")

        # Start Wireshark filtered to show all matching packets (request + response)
        wireshark_process = subprocess.Popen([
            "wireshark",
            "-r", pcap,
            "-Y", ws_filter
        ])

        # Wait for Wireshark to fully load
        time.sleep(4)

        # Fullscreen before capture
        subprocess.run(["xdotool", "key", "F11"])
        time.sleep(0.5)

        # Take screenshot
        subprocess.run(["scrot", screenshot_file])
        logger.info(f"Packet screenshot saved: {screenshot_file}")

        # Restore window size
        subprocess.run(["xdotool", "key", "F11"])

        # Close Wireshark
        logger.info("Closing Wireshark")
        wireshark_process.terminate()
        time.sleep(2)

        try:
            wireshark_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            wireshark_process.kill()

        return screenshot_file
