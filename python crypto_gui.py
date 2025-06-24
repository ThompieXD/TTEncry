# Imports
import customtkinter as ctk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import secrets
import random
import re
import threading
from datetime import datetime
import tkinter as tk
import sys
import os

# Main Fuction's
def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def generate_token():
    return secrets.token_hex(16)

def encrypt(plaintext):
    token = generate_token()
    salt = get_random_bytes(16)
    key = PBKDF2(token, salt, dkLen=32, count=100_000)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode()))
    encrypted_data = base64.b64encode(salt + iv + encrypted).decode()
    return encrypted_data, token

def decrypt(encrypted_data, token):
    try:
        data = base64.b64decode(encrypted_data)
        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]
        key = PBKDF2(token, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return unpad(decrypted).decode()
    except Exception:
        return "[Fout: verkeerde token of corrupte data]"

def show_temp_notification(text, color="green", duration=2):
    notification_label.configure(text=text, text_color=color)
    notification_label.pack(pady=5)
    def hide_label():
        import time
        time.sleep(duration)
        notification_label.configure(text="")
        notification_label.pack_forget()
    threading.Thread(target=hide_label, daemon=True).start()

def encrypt_text():
    message = input_box.get("0.0", "end").strip()
    if not message:
        show_temp_notification("⚠️ Vul tekst in om te versleutelen.", color="orange")
        return
    encrypted, token = encrypt(message)
    output_box.delete("0.0", "end")
    output_box.insert("0.0", encrypted)
    token_entry.delete(0, "end")
    token_entry.insert(0, token)
    now = datetime.now().strftime("%H:%M:%S")
    num = random.randint(0, 999)
    history_box.insert("0.0", f"[{now}] | [{num}] Token: {token}\n")

def decrypt_text():
    full_input = input_box.get("0.0", "end").strip()
    token = token_entry.get().strip()
    if not token:
        match = re.search(r'Token:\s*"([^"]+)"', full_input)
        if match:
            token = match.group(1)
            token_entry.delete(0, "end")
            token_entry.insert(0, token)
            full_input = re.sub(r'Token:\s*".*?"', '', full_input).strip().strip('"')
    if not full_input or not token:
        show_temp_notification("⚠️ Vul tekst én token in.", color="orange")
        return
    result = decrypt(full_input, token)
    output_box.delete("0.0", "end")
    output_box.insert("0.0", result)
    if result.startswith("[Fout"):
        show_temp_notification("❌ Ongeldige token of corrupte data.", color="red")
    else:
        show_temp_notification("✔️ Ontsleuteling geslaagd!", color="green")

def copy_token_and_text():
    token = token_entry.get().strip()
    text = output_box.get("0.0", "end").strip()
    if not token or not text:
        show_temp_notification("⚠️ Geen tekst of token beschikbaar.", color="orange")
        return
    formatted = f'"{text}"\nToken: "{token}"'
    app.clipboard_clear()
    app.clipboard_append(formatted)
    show_temp_notification("✔️ Gekopieerd naar klembord!", color="green")

def clear_output_on_input(*args):
    output_box.delete("0.0", "end")
    token_entry.delete(0, "end")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("TTEncry")
app.geometry("900x700")
if sys.platform.startswith('win'):
    try:
        icon_path = os.path.abspath("logo.ico")
        icon_image = tk.PhotoImage(file=icon_path)
        app.wm_iconbitmap(icon_path)
    except Exception as e:
        print(f"Icon error: {e}")
else:
    print("Fuck Linux")

canvas = ctk.CTkCanvas(app, bg="#0a0a0a", highlightthickness=0)
canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
canvas.lower("all")

stars = []

def create_stars():
    stars.clear()
    canvas.delete("all")
    width = canvas.winfo_width()
    height = canvas.winfo_height()
    for _ in range(100):
        x = random.randint(0, width)
        y = random.randint(0, height)
        size = random.choice([1, 2])
        speed = random.uniform(0.5, 1.5)
        star = canvas.create_oval(x, y, x+size, y+size, fill="white", outline="")
        stars.append({"id": star, "x": x, "y": y, "speed": speed, "size": size})

def animate_stars():
    width = canvas.winfo_width()
    height = canvas.winfo_height()
    for star in stars:
        star["y"] += star["speed"]
        if star["y"] > height:
            star["y"] = 0
            star["x"] = random.randint(0, width)
        canvas.coords(star["id"], star["x"], star["y"], star["x"] + star["size"], star["y"] + star["size"])
    app.after(34, animate_stars)

canvas.bind("<Configure>", lambda e: create_stars())
create_stars()
animate_stars()

# Layoutje voor de GUI
title = ctk.CTkLabel(app, text="TokenEncryptor", font=ctk.CTkFont(size=24, weight="bold"))
title.pack(pady=15)

input_label = ctk.CTkLabel(app, text="Tekst (versleuteld of onversleuteld):")
input_label.pack()

input_box = ctk.CTkTextbox(app, height=120, fg_color=("#000000", "#1a1a1a"), text_color="white", corner_radius=8)
input_box.pack(padx=20, pady=10, fill="both")
input_box.bind("<Key>", clear_output_on_input)

token_frame = ctk.CTkFrame(app, fg_color=("#000000", "#1a1a1a"))
token_frame.pack(pady=10)

token_label = ctk.CTkLabel(token_frame, text="Token:")
token_label.grid(row=0, column=0, padx=5)

token_entry = ctk.CTkEntry(token_frame, width=300, fg_color="#1a1a1a", text_color="white")
token_entry.grid(row=0, column=1, padx=(5, 0))

copy_button = ctk.CTkButton(token_frame, text="📋 Kopieer tekst + token", command=copy_token_and_text)
copy_button.grid(row=0, column=2, padx=5)

button_frame = ctk.CTkFrame(app, fg_color="transparent")
button_frame.pack(pady=10)

encrypt_button = ctk.CTkButton(button_frame, text="Versleutel", command=encrypt_text, width=150)
encrypt_button.pack(side="left", padx=20)

decrypt_button = ctk.CTkButton(button_frame, text="Ontsleutel", command=decrypt_text, width=150)
decrypt_button.pack(side="left", padx=20)

notification_label = ctk.CTkLabel(app, text="", text_color="green", font=ctk.CTkFont(size=14, weight="bold"))

output_label = ctk.CTkLabel(app, text="Resultaat:")
output_label.pack()
output_box = ctk.CTkTextbox(app, height=120, fg_color="#1a1a1a", text_color="white", corner_radius=8)
output_box.pack(padx=20, pady=10, fill="both")

history_label = ctk.CTkLabel(app, text="🕓 Geschiedenis gegenereerde tokens:")
history_label.pack()
history_box = ctk.CTkTextbox(app, height=100, fg_color="#1a1a1a", text_color="white", corner_radius=8)
history_box.pack(padx=20, pady=5, fill="both")

app.mainloop()