import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
from openai import OpenAI
from pathlib import Path
import sys
import os
from dotenv import load_dotenv
from models import soc_assistant
from utils import utils
import pandas as pd


# LOAD ENVIRONMENT VARIABLES
BASE_DIR = Path(__file__).resolve().parent
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not found. Check your .env file.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# TIMESTAMP NORMALIZATION
def normalize_timestamp_column(ts_col):
    """
    Convert a Pandas Series of timestamps to Timedelta.
    Handles:
    - strings in MM:SS
    - numbers (seconds) as float/int
    """
    if ts_col.dtype.kind in {'i', 'f'}:  # numeric seconds
        return pd.to_timedelta(ts_col, unit='s')
    elif ts_col.dtype == 'O':  # object/string type
        return pd.to_timedelta('00:' + ts_col)
    else:
        raise ValueError(f"Unsupported Timestamp column dtype: {ts_col.dtype}")

def parse_mmss(time_str):
    """Parse MM:SS string into pandas Timedelta"""
    try:
        minutes, seconds = map(int, time_str.strip().split(":"))
        return pd.Timedelta(minutes=minutes, seconds=seconds)
    except Exception:
        raise ValueError("Time must be in MM:SS format, e.g., 59:50")


# GUI FUNCTIONS
def append_output(text):
    output_text.config(state="normal")
    output_text.insert(tk.END, text)
    output_text.see(tk.END)
    output_text.config(state="disabled")

def run_simulation(n, start_time, end_time):
    try:
        append_output("Starting AI Simulation...\n\n")
        openai_client = OpenAI(api_key=OPENAI_API_KEY)

        # allowed_labels = ["BENIGN", "DDoS", "Portscan", "BruteForce", "Botnet"]
        allowed_labels = ["BENIGN", "Portscan"]
        X, Y = utils.get_balanced_subset(allowed_labels=allowed_labels)

        # Normalize timestamps safely
        X["Timestamp"] = normalize_timestamp_column(X["Timestamp"])

        start_td = parse_mmss(start_time)
        end_td   = parse_mmss(end_time)

        # Filter dataset
        X = X[(X["Timestamp"] >= start_td) & (X["Timestamp"] <= end_td)]

        flow_rows = X.head(n).filter(items=[
            "Src IP dec", "Src Port", "Dst IP dec", "Dst Port",
            "Protocol", "Timestamp", "Flow Duration",
            "Total Fwd Packet", "Total Bwd packets",
            "Total Length of Bwd Packet", "Total Length of Fwd Packet",
            "SYN Flag Count", "ACK Flag Count", "RST Flag Count",
            "FIN Flag Count"
        ])

        labels = Y.loc[flow_rows.index, "Label"].reset_index(drop=True)

        total = 0
        correct = 0
        true_pos = true_neg = false_pos = false_neg = 0

        prompt_path = BASE_DIR / "prompts" / "aggressive.txt"
        prompt_text = prompt_path.read_text(encoding="utf-8")

        root.after(0, lambda: (
            progress.config(maximum=len(flow_rows), value=0),
            progress_label.config(text="0%")
        ))

        for i, (_, row) in enumerate(flow_rows.iterrows()):
            check = soc_assistant.openai_risk_filter(
                openai_client,
                row.to_dict(),
                prompt_text,
            )

            result_label = check.attack_type
            gt_label = labels.iloc[i]

            if gt_label == result_label:
                if gt_label == "BENIGN":
                    true_neg += 1
                else:
                    true_pos += 1
                correct += 1
            else:
                if gt_label == "BENIGN":
                    false_pos += 1
                else:
                    false_neg += 1

            total += 1
            append_output(f"Network Flow Data{i} | Ground Truth: {gt_label} | LLM Result: {result_label}\n")

            percent_complete = int(((i + 1) / len(flow_rows)) * 100)
            root.after(0, lambda val=i+1, perc=percent_complete: (
                progress.config(value=val),
                progress_label.config(text=f"{perc}%")
            ))

        accuracy = (correct / total) * 100 if total else 0
        precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) else 0
        recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) else 0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0

        append_output("\n===== FINAL REPORT =====\n")
        append_output(f"Accuracy: {round(accuracy, 2)}%\n")
        append_output(f"TP: {true_pos} | TN: {true_neg} | FP: {false_pos} | FN: {false_neg}\n")
        append_output(f"Precision: {round(precision, 4)}\n")
        append_output(f"Recall: {round(recall, 4)}\n")
        append_output(f"F1 Score: {round(f1, 4)}\n")

    except Exception as e:
        root.after(0, lambda msg=str(e): messagebox.showerror("Error", msg))

def start_ai():
    try:
        n = int(n_entry.get())
        start_time = start_entry.get()
        end_time = end_entry.get()

        # Validate input
        try:
            start_td = parse_mmss(start_time)
            end_td   = parse_mmss(end_time)
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return
        if end_td <= start_td:
            messagebox.showerror("Input Error", "End time must be after start time.")
            return

        output_text.config(state="normal")
        output_text.delete(1.0, tk.END)
        output_text.config(state="disabled")
        progress.config(value=0)
        progress_label.config(text="0%")

        thread = Thread(target=run_simulation, args=(n, start_time, end_time), daemon=True)
        thread.start()

    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid number of samples.")

# GUI SETUP
root = tk.Tk()
root.title("SOC AI Accuracy Checker")
root.geometry("900x650")

container = ttk.Frame(root)
container.pack(expand=True)
frame = ttk.Frame(container, padding=20)
frame.grid(row=0, column=0)

frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)

# Default values
default_start_str = "00:00"
default_end_str   = "59:50"

ttk.Label(frame, text="Start Time (MM:SS) e.g. 00:00").grid(row=0, column=0, columnspan=2, pady=(5,2))
start_entry = ttk.Entry(frame, width=15, justify="center")
start_entry.insert(0, default_start_str)
start_entry.grid(row=1, column=0, columnspan=2, pady=5)

ttk.Label(frame, text="End Time (MM:SS) e.g. 59:50").grid(row=2, column=0, columnspan=2, pady=(10,2))
end_entry = ttk.Entry(frame, width=15, justify="center")
end_entry.insert(0, default_end_str)
end_entry.grid(row=3, column=0, columnspan=2, pady=5)

ttk.Label(frame, text="Number of Samples:").grid(row=4, column=0, columnspan=2, pady=(10,2))
n_entry = ttk.Entry(frame, width=15, justify="center")
n_entry.insert(0, "5")
n_entry.grid(row=5, column=0, columnspan=2, pady=5)

start_button = ttk.Button(frame, text="Start AI", command=start_ai)
start_button.grid(row=6, column=0, columnspan=2, pady=15)

progress_frame = ttk.Frame(root)
progress_frame.pack(pady=10)
progress = ttk.Progressbar(progress_frame, orient="horizontal", length=400, mode="determinate")
progress.pack(side="left", padx=(0,10))
progress_label = ttk.Label(progress_frame, text="0%")
progress_label.pack(side="left")

output_text = tk.Text(root, wrap="word", state="disabled")
output_text.pack(fill="both", expand=True, padx=20, pady=10)

root.mainloop()