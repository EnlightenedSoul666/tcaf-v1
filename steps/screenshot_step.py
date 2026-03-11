import subprocess
from core.step import Step
from utils.logger import logger
import time

class ScreenshotStep(Step):

    def __init__(self, terminal):
        super().__init__("Capture screenshot")
        self.terminal = terminal
        self.suffix = f"_{suffix}" if suffix else ""

    def execute(self, context):
        # 1. Get the path and filename (you already have this logic)
        clause = context.clause
        testcase = context.current_testcase
        path = context.evidence.testcase_dir(clause, testcase)
        base_name = f"{self.terminal}{self.suffix}.png"
        timestamped_name = context.evidence.get_timestamped_filename(base_name)
        screenshot_file = f"{path}/screenshots/{timestamped_name}"
        
        # 2. Get the window ID 
        # (Adjust this variable name to match however you log "tester window id" in your code)
        window_id = context.tester_window_id 

        logger.info(f"Maximizing terminal window {window_id} for screenshot")

        # 3. Bring the terminal to the front and press F11 (Fullscreen)
        subprocess.run(["xdotool", "windowactivate", str(window_id)])
        subprocess.run(["xdotool", "key", "F11"])
        
        # Give the GUI a half-second to finish the resizing animation
        time.sleep(0.5) 

        # 4. Take the screenshot (Keep your existing screenshot logic here)
        logger.info(f"Capturing screenshot: {screenshot_file}")
        # e.g., subprocess.run(["scrot", "-u", screenshot_file]) or pyautogui, etc.
        
        # 5. Restore the window to its original size by pressing F11 again
        subprocess.run(["xdotool", "key", "F11"])
        logger.info("Restored terminal to original size")