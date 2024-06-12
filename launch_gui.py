import tkinter as tk
from Karloss.gui import ConfigurationWindow

def main():
    # Launch the configuration window
    config_root = tk.Tk()
    config_app = ConfigurationWindow(config_root)
    config_root.mainloop()

if __name__ == "__main__":
    main()
