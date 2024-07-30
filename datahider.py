from tkinter import *
from tkinter import filedialog, messagebox
import tkinter as tk
from PIL import Image, ImageTk
import os
from stegano import lsb
from cryptography.fernet import Fernet
import base64
import hashlib

root = Tk()
root.title("Steganography - datahider")
root.geometry("750x515")
root.resizable(False, False)
root.configure(bg="#CCCCFF")

filename = ""
secret = None

def generate_key(password):
    # Ensure the password is encoded correctly
    password_bytes = password.encode()
    # Create a SHA-256 hash of the password
    hash_obj = hashlib.sha256(password_bytes).digest()
    # Use the first 32 bytes of the hash to generate the key
    key = base64.urlsafe_b64encode(hash_obj[:32])
    return key

def encrypt_message(message, password):
    key = generate_key(password)
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(message.encode())
    return cipher_text

def decrypt_message(cipher_text, password):
    key = generate_key(password)
    cipher_suite = Fernet(key)
    try:
        plain_text = cipher_suite.decrypt(cipher_text).decode()
        return plain_text
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {e}")
        return None

def showimage():
    global filename
    filename = filedialog.askopenfilename(initialdir=os.getcwd(),
                                          title='Select Image File',
                                          filetype=(("PNG file", "*.png"),
                                                    ("JPG file", "*.jpg"),
                                                    ("All file", "*.*")))
    if filename:
        img = Image.open(filename)
        img = ImageTk.PhotoImage(img)
        lbl.configure(image=img, width=250, height=250)
        lbl.image = img

def Hide():
    global secret
    if filename:
        message = text1.get(1.0, END).strip()
        password = password_entry.get().strip()
        if message and password:
            try:
                encrypted_message = encrypt_message(message, password)
                secret = lsb.hide(str(filename), encrypted_message.decode())
                messagebox.showinfo("Success", "Message hidden successfully!")
                # Prompt user to save the image immediately after hiding the message
                save()
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
        else:
            messagebox.showwarning("Warning", "Please enter both message and password.")
    else:
        messagebox.showwarning("Warning", "Please select an image file first.")

def Show():
    if filename:
        password = password_entry.get().strip()
        if password:
            try:
                hidden_message = lsb.reveal(filename)
                if hidden_message:
                    decrypted_message = decrypt_message(hidden_message.encode(), password)
                    if decrypted_message:
                        text1.delete(1.0, END)
                        text1.insert(END, decrypted_message)
                else:
                    messagebox.showinfo("No Message", "No hidden message found in the image.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
        else:
            messagebox.showwarning("Warning", "Please enter the password.")
    else:
        messagebox.showwarning("Warning", "Please select an image file first.")

def save():
    if secret:
        try:
            save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                     filetypes=[("PNG file", "*.png")])
            if save_path:
                secret.save(save_path)
                messagebox.showinfo("Success", "Image saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    else:
        messagebox.showwarning("Warning", "No hidden message found. Please hide a message first.")

# Icon
image_icon = PhotoImage(file="logo.jpg")
root.iconphoto(False, image_icon)

# Logo
logo = PhotoImage(file="logo.png")
Label(root, image=logo, bg="#CCCCFF").place(x=15, y=14)

Label(root, text="STEGANOGRAPHY", bg="#CCCCFF", fg="black", font="arial 25 bold").place(x=70, y=20)

# First frame
f = Frame(root, bd=3, bg="black", width=340, height=280, relief=GROOVE)
f.place(x=10, y=80)

lbl = Label(f, bg="black")
lbl.place(x=40, y=10)

# Second frame
frame2 = Frame(root, bd=3, width=340, height=280, bg="white", relief=GROOVE)
frame2.place(x=350, y=80)

text1 = Text(frame2, font="Roboto 20", bg="white", fg="black", relief=GROOVE, wrap=WORD)
text1.place(x=0, y=0, width=320, height=295)

scrollbar1 = Scrollbar(frame2)
scrollbar1.place(x=320, y=0, height=300)

scrollbar1.configure(command=text1.yview)
text1.configure(yscrollcommand=scrollbar1.set)

# Third frame
frame3 = Frame(root, bd=3, bg="#D7BDE2", width=330, height=100, relief=GROOVE)
frame3.place(x=10, y=370)

Button(frame3, text="Open Image", width=10, height=2, font="arial 14 bold", bg="#EBDEF0", fg="black", command=showimage).place(x=20, y=30)
Button(frame3, text="Save Image", width=10, height=2, font="arial 14 bold", bg="#EBDEF0", fg="black", command=save).place(x=180, y=30)
Label(frame3, text="Picture, Image, Photo file", bg="#D7BDE2", fg="black").place(x=20, y=5)

# Fourth frame
frame4 = Frame(root, bd=3, bg="#D7BDE2", width=330, height=100, relief=GROOVE)
frame4.place(x=360, y=370)

Button(frame4, text="Hide Data", width=10, height=2, font="arial 14 bold", bg="#EBDEF0", fg="black", command=Hide).place(x=20, y=30)
Button(frame4, text="Show Data", width=10, height=2, font="arial 14 bold", bg="#EBDEF0", fg="black", command=Show).place(x=180, y=30)
Label(frame4, text="Picture, Image, Photo file", bg="#D7BDE2", fg="black").place(x=20, y=5)

# Password entry
password_label = Label(root, text="Password:", bg="#CCCCFF", fg="black", font="arial 12 bold")
password_label.place(x=10, y=480)
password_entry = Entry(root, show="*", font="arial 12")
password_entry.place(x=120, y=480)

root.mainloop()

