import base64
import requests
import tkinter as tk
from tkinter import *
from tkinter import ttk, messagebox


VT_API_KEY = "[ENTER_YOUR_API_KEY_HERE]"
BASE_URL= "https://www.virustotal.com/api/v3/"
HEADERS = {"x-apikey": VT_API_KEY}


#VT Functions
def check_domain(domain: str):
    #Check domain reputation in VirusTotal
    resp = requests.get(BASE_URL + f"domains/{domain}", headers=HEADERS)
    return resp.json()

def check_url(url: str):
    #Check URL reputation in VirusTotal
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    resp = requests.get(BASE_URL + f"urls/{encoded}", headers=HEADERS)
    return resp.json()

def check_ip(ip: str):
    #Check IP address reputation in VirusTotal
    resp = requests.get(BASE_URL + f"ip_addresses/{ip}", headers=HEADERS)
    return resp.json()


#Functions for GUI
def run_check():
    input_value = entry.get().strip()
    option = combo.get()

    if not input_value:
        messagebox.showwarning("Input Error", "Please enter a value.")
        return
    
    try:
        if option == "Domain":
            result = check_domain(input_value)
        elif option == "URL":
            result = check_url(input_value)
        elif option == "IP Address":
            result = check_ip(input_value)
        else:
            messagebox.showerror("Error", "Invalid option")
            return
        
    
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        text.delete("1.0", tk.END)
        
        if not stats:
            text.insert(tk.END, "No results available. \n")
            return
        
        text.insert(tk.END, f"Malicious: {stats.get('malicious', 0)}\n")
        text.insert(tk.END, f"Suspicious: {stats.get('suspicious', 0)}\n")
        text.insert(tk.END, f"Harmless: {stats.get('harmless', 0)}\n")
        text.insert(tk.END, f"Undetected: {stats.get('undetected', 0)}\n")

    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")


#GUI SECTION

root = Tk()
root.title("PhishSpy")
root.geometry("800x400")

frm = ttk.Frame(root, padding=10)
frm.grid(row=0, column=0, sticky="nsew")

#Input form label + text entry
ttk.Label(frm, text="Enter Domain / URL / IP:").grid(column=0, row=0, padx=5, pady=5, sticky="w")
entry = ttk.Entry(frm, width=40)
entry.grid(row=0, column=1, padx=5, pady=5)


#Dropdown
combo = ttk.Combobox(frm, values=["Domain", "URL", "IP Address"], state="readonly")
combo.grid(row=0, column=2, padx=5, pady=5)
combo.current(0)

#Buttons
check_button = ttk.Button(frm, text="Check", command=run_check)
check_button.grid(row=0, column=3, padx=5, pady=5)

quit_button = ttk.Button(frm, text="Quit", command=root.destroy).grid(column=6, row=0)


#Results text box
text = tk.Text(frm, width=70, height=10)
text.grid(row=1, column=0, columnspan=4, padx=5, pady=10)

root.mainloop()
