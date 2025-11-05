import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import xml.etree.ElementTree as ET
import requests
import os
import datetime

# ------------------- Configuration -------------------
NMAP_PATH = "nmap"  # default path; Codespaces / Linux will find it in PATH
OUTPUT_DIR = os.path.join(os.getcwd(), "scan_results")
VULNERS_API = "https://vulners.com/api/v3/search/lucene/?query="

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# ------------------- GUI Setup -------------------
root = tk.Tk()
root.title("PyZenmap – Advanced Nmap GUI with Vulnerability Analysis")
root.geometry("1000x700")

tab_control = ttk.Notebook(root)

# Tabs
scan_tab = ttk.Frame(tab_control)
result_tab = ttk.Frame(tab_control)
vuln_tab = ttk.Frame(tab_control)

tab_control.add(scan_tab, text="Scan")
tab_control.add(result_tab, text="Results")
tab_control.add(vuln_tab, text="Vulnerability Analysis")
tab_control.pack(expand=1, fill="both")

# ------------------- Scan Tab -------------------
tk.Label(scan_tab, text="Target:").grid(row=0, column=0, padx=10, pady=10)
target_entry = tk.Entry(scan_tab, width=50)
target_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(scan_tab, text="Scan Type:").grid(row=1, column=0, padx=10, pady=10)
scan_type = ttk.Combobox(scan_tab, values=["-sS (TCP SYN)", "-sU (UDP)", "-A (Aggressive)", "-F (Fast)"])
scan_type.grid(row=1, column=1, padx=10, pady=10)
scan_type.set("-A (Aggressive)")

tk.Label(scan_tab, text="Additional Options:").grid(row=2, column=0, padx=10, pady=10)
extra_options = tk.Entry(scan_tab, width=50)
extra_options.grid(row=2, column=1, padx=10, pady=10)

def run_scan():
    target = target_entry.get()
    scan_option = scan_type.get().split(" ")[0]
    extra = extra_options.get()

    if not target:
        messagebox.showwarning("Input Error", "Please enter a target.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_xml = os.path.join(OUTPUT_DIR, f"scan_{timestamp}.xml")

    cmd = f"{NMAP_PATH} {scan_option} {extra} -oX {output_xml} {target}"

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"[Running]: {cmd}\n\n")

    try:
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        result_text.insert(tk.END, process.stdout)
        result_text.insert(tk.END, "\n[Scan Completed]\n")
        messagebox.showinfo("Success", f"Scan completed.\nSaved: {output_xml}")
        parse_results(output_xml)
    except Exception as e:
        messagebox.showerror("Error", str(e))

tk.Button(scan_tab, text="Start Scan", command=run_scan, bg="green", fg="white").grid(row=3, column=1, pady=20)

# ------------------- Results Tab -------------------
result_text = scrolledtext.ScrolledText(result_tab, wrap=tk.WORD, width=120, height=30)
result_text.pack(padx=10, pady=10, fill="both", expand=True)

# ------------------- Vulnerability Tab -------------------
vuln_text = scrolledtext.ScrolledText(vuln_tab, wrap=tk.WORD, width=120, height=30)
vuln_text.pack(padx=10, pady=10, fill="both", expand=True)

def parse_results(xml_file):
    vuln_text.delete(1.0, tk.END)

    if not os.path.exists(xml_file):
        vuln_text.insert(tk.END, "No XML file found.\n")
        return

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        hosts = root.findall("host")

        for host in hosts:
            ip = host.find("address").attrib["addr"]
            vuln_text.insert(tk.END, f"\nTarget: {ip}\n" + "-" * 80 + "\n")
            ports = host.findall(".//port")
            for port in ports:
                portid = port.attrib["portid"]
                protocol = port.attrib["protocol"]
                state = port.find("state").attrib["state"]
                service_el = port.find("service")
                service = service_el.attrib.get("name", "unknown") if service_el is not None else "unknown"
                version = service_el.attrib.get("version", "") if service_el is not None else ""

                vuln_text.insert(tk.END, f"Port {portid}/{protocol} - {service} ({state}) {version}\n")

                # Search vulnerabilities
                query = f"{service} {version}"
                vulns = search_vulnerabilities(query)
                if vulns:
                    for v in vulns:
                        vuln_text.insert(tk.END, f"  ⚠️ {v['id']} - {v['title']}\n")
                else:
                    vuln_text.insert(tk.END, "  No known vulnerabilities found.\n")
                vuln_text.insert(tk.END, "\n")

    except Exception as e:
        vuln_text.insert(tk.END, f"Error parsing results: {e}\n")

def search_vulnerabilities(query):
    try:
        response = requests.get(VULNERS_API + query, timeout=10)
        data = response.json()
        results = []
        if "data" in data and "search" in data["data"]:
            for item in data["data"]["search"]:
                results.append({"id": item["id"], "title": item["title"]})
        return results
    except Exception as e:
        print(f"Error fetching vulnerabilities: {e}")
        return []

# ------------------- Run GUI -------------------
root.mainloop()
