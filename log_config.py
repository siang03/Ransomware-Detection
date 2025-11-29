import logging
import sys

def setup_logging():
    # Reset any previous configuration (optional, use with care)
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    logging.basicConfig(
        level=logging.INFO,
        filename="application.log",
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Add a console handler to show logs on the terminal
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

# Immediately call setup_logging() when this module is imported
setup_logging()
