import tkinter as tk
from tkinter import messagebox, ttk
from pymongo import MongoClient
import bcrypt
import re

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['user_credentials']
collection = db['users']

# Function to validate login
def validate_login():
    username = username_entry.get().strip()
    password = password_entry.get().strip()
    user = collection.find_one({'username': username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        messagebox.showinfo("Login Successful", f"Welcome, {username}!")
        display_drawing()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

# Function to validate registration
def validate_registration():
    new_username = new_username_entry.get().strip()
    new_password = new_password_entry.get().strip()
    new_email = new_email_entry.get().strip()
    terms_accepted = terms_var.get()
    
    if not new_username or not new_password or not new_email:
        messagebox.showerror("Registration Failed", "All fields are required!")
        return

    if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
        messagebox.showerror("Registration Failed", "Invalid email format!")
        return

    if len(new_password) < 8 or not re.search(r"[A-Z]", new_password) or not re.search(r"[a-z]", new_password) or not re.search(r"[0-9]", new_password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
        messagebox.showerror("Registration Failed", "Password must be at least 8 characters long and include an upper case letter, a lower case letter, a number, and a special character!")
        return

    if not terms_accepted:
        messagebox.showerror("Registration Failed", "You must accept the terms and conditions!")
        return

    if collection.find_one({'username': new_username}):
        messagebox.showerror("Registration Failed", "Username already exists!")
    else:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        collection.insert_one({'username': new_username, 'password': hashed_password, 'email': new_email})
        messagebox.showinfo("Registration Successful", "You have been registered successfully!")
        show_login_page()

# Function to display the drawing
def display_drawing():
    import display_drawing

# Creating main window
root = tk.Tk()
root.title("Doraemon Program Login")

# Styling
style = ttk.Style()
style.configure("TButton", font=("Helvetica", 12))
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TEntry", font=("Helvetica", 12))

# Login Page
login_frame = ttk.Frame(root)
login_frame.pack(padx=20, pady=20)

login_label = ttk.Label(login_frame, text="Login", font=("Helvetica", 16))
login_label.grid(row=0, column=0, columnspan=2, pady=10)

username_label = ttk.Label(login_frame, text="Username:")
username_label.grid(row=1, column=0, pady=5)

username_entry = ttk.Entry(login_frame)
username_entry.grid(row=1, column=1, pady=5)

password_label = ttk.Label(login_frame, text="Password:")
password_label.grid(row=2, column=0, pady=5)

password_entry = ttk.Entry(login_frame, show="*")
password_entry.grid(row=2, column=1, pady=5)

login_button = ttk.Button(login_frame, text="Login", command=validate_login)
login_button.grid(row=3, column=0, columnspan=2, pady=10)

# Registration Page
registration_frame = ttk.Frame(root)

registration_label = ttk.Label(registration_frame, text="Registration", font=("Helvetica", 16))
registration_label.grid(row=0, column=0, columnspan=2, pady=10)

new_username_label = ttk.Label(registration_frame, text="New Username:")
new_username_label.grid(row=1, column=0, pady=5)

new_username_entry = ttk.Entry(registration_frame)
new_username_entry.grid(row=1, column=1, pady=5)

new_password_label = ttk.Label(registration_frame, text="New Password:")
new_password_label.grid(row=2, column=0, pady=5)

new_password_entry = ttk.Entry(registration_frame, show="*")
new_password_entry.grid(row=2, column=1, pady=5)

new_email_label = ttk.Label(registration_frame, text="Email:")
new_email_label.grid(row=3, column=0, pady=5)

new_email_entry = ttk.Entry(registration_frame)
new_email_entry.grid(row=3, column=1, pady=5)

terms_var = tk.BooleanVar()
terms_check = ttk.Checkbutton(registration_frame, text="I accept the terms and conditions", variable=terms_var)
terms_check.grid(row=4, column=0, columnspan=2, pady=5)

register_button = ttk.Button(registration_frame, text="Register", command=validate_registration)
register_button.grid(row=5, column=0, columnspan=2, pady=10)

# Hide registration frame initially
registration_frame.pack_forget()

# Function to switch between login and registration pages
def show_registration_page():
    login_frame.pack_forget()
    registration_frame.pack(padx=20, pady=20)

def show_login_page():
    registration_frame.pack_forget()
    login_frame.pack(padx=20, pady=20)

# Add buttons to switch between login and registration pages
switch_to_registration_button = ttk.Button(root, text="Register", command=show_registration_page)
switch_to_registration_button.pack(side=tk.LEFT, padx=10)

switch_to_login_button = ttk.Button(root, text="Back to Login", command=show_login_page)
switch_to_login_button.pack(side=tk.RIGHT, padx=10)

root.mainloop()
