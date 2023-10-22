import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
from functools import partial
import requests
from multiprocessing.dummy import Pool as ThreadPool

def check(email, verbose='no'):
    url = "https://mail.google.com/mail/gxlu?email={0}".format(email)
    r = requests.get(url)

    try:
        if r.headers['set-cookie'] != '':
            if verbose == 'yes':
                print(r.headers)
            return email
    except:
        if verbose == 'yes':
            print(r.headers)
        return

def write_to_file(hnd, data):
    for d in data:
        if d is not None:
            hnd.write(str(d + "\n"))

def write_to_results(data):
    for d in data:
        if d is not None:
            results_text.insert(tk.END, f"{d} address valid\n", "valid")
        else:
            results_text.insert(tk.END, "Invalid address\n", "invalid")

def run_checker():
    email = email_entry.get()
    if email:
        result = check(email, verbose=verbose.get())
        if result is None:
            results_text.insert(tk.END, f"{email} address not valid\n", "invalid")
        else:
            results_text.insert(tk.END, f"{email} address valid\n", "valid")
    else:
        messagebox.showerror("Error", "Please enter an email address")

def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        filename_entry.delete(0, tk.END)
        filename_entry.insert(0, file_path)

def process_file():
    filename = filename_entry.get()
    if filename:
        with open(filename) as fp:
            emails = [line.strip() for line in fp]
        results = pool.map(partial(check, verbose=verbose.get()), emails)
        output_file = out_file_entry.get()
        if output_file:
            with open(output_file, "w") as out_file:
                write_to_file(out_file, results)
            messagebox.showinfo("Result", "Processing completed")
        else:
            write_to_results(results)
    else:
        messagebox.showerror("Error", "Please select a file")

def main():
    global email_entry, verbose, results_text, filename_entry, pool, out_file_entry

    root = tk.Tk()
    root.title("Gmail Checker")
    root.geometry("800x400")

    # Emailchck
    check_frame = ttk.LabelFrame(root, text="Email Check")
    check_frame.pack(pady=10, padx=10, fill="x")

    ttk.Label(check_frame, text="Email Address:").grid(row=0, column=0, padx=(0, 5))
    email_entry = ttk.Entry(check_frame, width=40)
    email_entry.grid(row=0, column=1, padx=(0, 10))

    verbose = tk.StringVar(value="no")
    verbose_checkbox = ttk.Checkbutton(check_frame, text="Verbose Output", variable=verbose, onvalue="yes", offvalue="no")
    verbose_checkbox.grid(row=0, column=2)

    ttk.Button(check_frame, text="Check", command=run_checker).grid(row=0, column=3, padx=(10, 0))

    # File proC
    file_frame = ttk.LabelFrame(root, text="File Processing")
    file_frame.pack(pady=10, padx=10, fill="x")

    ttk.Label(file_frame, text="File Name:").grid(row=0, column=0, padx=(0, 5))
    filename_entry = ttk.Entry(file_frame, width=40)
    filename_entry.grid(row=0, column=1, padx=(0, 10))

    ttk.Button(file_frame, text="Browse", command=browse_file).grid(row=0, column=2)

    ttk.Button(file_frame, text="Process File", command=process_file).grid(row=0, column=3, padx=(10, 0))

    # Output
    output_frame = ttk.LabelFrame(root, text="Output Options")
    output_frame.pack(pady=10, padx=10, fill="x")

    ttk.Label(output_frame, text="Output File Name (optional):").grid(row=0, column=0, padx=(0, 5))
    out_file_entry = ttk.Entry(output_frame, width=40)
    out_file_entry.grid(row=0, column=1)

    # Results
    results_frame = ttk.LabelFrame(root, text="Results")
    results_frame.pack(pady=10, padx=10, fill="both", expand=True)

    global results_text
    results_text = tk.Text(results_frame, width=70, height=10)
    results_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

    results_text.tag_configure("valid", foreground="green")
    results_text.tag_configure("invalid", foreground="red")

    scroll_y = ttk.Scrollbar(results_frame, orient="vertical", command=results_text.yview)
    scroll_y.grid(row=0, column=1, sticky="ns")
    results_text.configure(yscrollcommand=scroll_y.set)

    pool = ThreadPool(20)

    root.mainloop()

if __name__ == "__main__":
    main()
