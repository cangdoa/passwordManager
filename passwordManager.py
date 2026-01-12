import tkinter as tk

from passwordManagerHelper import (
    retrieve_json,
    find_user,
    retrieve_user,
    check_passkey,
    new_user,
    write_to_json,
    check_service,
    add_service,
    remove_service,
    list_services
)

frames = []
deleted = False
current_email = None
current_passkey = None

# Reset the frames in the beginning
def reset_frame(frame):
    # Entities for passkeys should be fully reset to nothing
    passkey_entities = [passkey_entry_login, passkey_entry_reg, passkey_entry_reg_confirm,
                        passkey_label_login, passkey_label_reg, passkey_label_reg_confirm, login_result_label]
    # Entities for emails should be reset to default
    email_entities = [email_label_login, email_label_reg, email_entry_login, email_entry_reg]
    for widget in frame.winfo_children():
        if isinstance(widget, tk.Entry):
            widget.delete(0, tk.END)
        if widget in passkey_entities:
            widget.pack_forget()
        if widget in email_entities:
            widget.pack(pady=5)
            if widget == email_label_login:
                widget.config(text="Enter a email:")
            if widget == email_label_reg:
                widget.config(text="Register an email")

# Show the given frame
def show_frame(frame):
    for f in frames:
        f.pack_forget()
        reset_frame(f)
    frame.pack(fill="both", expand=True)

# Handles entering an email on the login frame
def submit_email_login(event=None):
    global current_email
    email = email_entry_login.get().strip()
    if not email:
        return
    if not find_user(email):
        email_label_login.config(text="No user with such email")
    else:
        email_label_login.config(text="Enter email")
        current_email = email
        passkey_label_login.pack(pady=5)
        passkey_entry_login.pack(pady=5)
        passkey_entry_login.focus_set()

# Handles entering the passkey on the login frame, verifying it matches the DB
def submit_passkey_login(event=None):
    global current_passkey
    passkey = passkey_entry_login.get().strip()
    if not passkey:
        return
    login_result_label.pack(pady=10)
    if check_passkey(current_email, passkey):
        current_passkey = passkey
        login_result_label.config(text="Logging in...")
        root.after(2000, lambda: show_frame(main_menu))
    else:
        login_result_label.config(text="Incorrect passkey")

# Handles registering a new email, verifying email isn't already in the DB
def submit_email_reg(event=None):
    global current_email
    email = email_entry_reg.get().strip()
    if not email:
        return
    if find_user(email):
        email_label_reg.config(text="User already exists with this email")
    else:
        email_label_reg.config(text="Register an email")
        current_email = email
        passkey_label_reg.pack(pady=5)
        passkey_entry_reg.pack(pady=5)
        passkey_entry_reg.focus_set()

# Handles creating a passkey for the new user
def submit_passkey_reg(event=None):
    passkey = passkey_entry_reg.get().strip()
    if not passkey:
        return
    passkey_label_reg_confirm.pack(pady=5)
    passkey_entry_reg_confirm.pack(pady=5)
    passkey_entry_reg_confirm.focus_set()

## Handles confirming a passkey for the new user and initialises them in the DB
def confirm_passkey(event=None):
    global current_passkey
    passkey = passkey_entry_reg_confirm.get().strip()
    if not passkey:
        return
    if passkey_entry_reg.get().strip() != passkey:
        passkey_label_reg_confirm.config(text="Passkeys not matching")
        passkey_entry_reg_confirm.delete(0, tk.END)
        return
    else:
        passkey_label_reg_confirm.config(text="Confirm passkey")
        current_passkey = passkey
        tk.Label(reg_menu, text="Registering account...", bg="lightblue", fg="darkblue", font=("Courier", 12)).pack(pady=5)
        new_user(current_email, current_passkey)
        root.after(2000, lambda: show_frame(main_menu))

# Clears the output box in the main menu
def clear_box():
    entry_boxes = [service_entry, password_entry, remove_service_entry, service_update, password_update]
    labels = [password_label, removed_label, password_set_label]
    for box in entry_boxes:
        if box.winfo_ismapped():
            box.pack_forget()
            box.delete(0, tk.END)
    for label in labels:
        if label.winfo_ismapped():
            label.pack_forget()

# Configures the label in the main menu to show the list of features
def show_help(event=None):
    clear_box()
    main_label.config(text="""Add service: add a password for a new service\n
    Remove service: removes a password for a service\n
    Update service: update a password for a service\n
    List services: lists all services and passwords\n
    Delete account: delete this account and its passwords""", font=("Courier", 8))

# Handles functionality when the "Add service" button is pressed
def enter_service(event=None):
    clear_box()
    main_label.config(text="Enter a service to add:", font=("Courier", 10))
    if not service_entry.winfo_ismapped():
        service_entry.pack(pady=5)
        service_entry.focus_set()

# Handles functionality for entering the password when "Add service" is pressed
# Verifies that the service isn't already in the DB
def enter_password(event=None):
    service = service_entry.get().strip()
    password_set_label.pack(pady=5)
    if check_service(current_email, service):
        password_entry.pack_forget()
        password_set_label.config(text="Service already in database")
        return
    password_set_label.config(text="Enter password:")
    if not password_entry.winfo_ismapped():
        password_entry.pack(pady=5)
        password_entry.focus_set()

# Sets the password in the DB once all checks clear
def password_set(event=None):
    password_set_label.pack(pady=5)
    service = service_entry.get().strip()
    password = password_entry.get().strip()
    add_service(current_email, service, current_passkey, password)
    password_set_label.config(text="Password set")

# Handles functionality when the "Update service" button is pressed
def update_service(event=None):
    clear_box()
    main_label.config(text="Enter a service to update:", font=("Courier", 10))
    if not service_update.winfo_ismapped():
        service_update.pack(pady=5)
        service_update.focus_set()

# Handles functionality for entering the password when "Update service" is pressed
# Verifies that the service is in the DBs
def update_password(event=None): 
    service = service_update.get().strip()
    password_set_label.pack(pady=5)
    if not check_service(current_email, service):
        password_update.pack_forget()
        password_set_label.config(text="Service not in database")
        return
    password_set_label.config(text="Enter password:")
    if not password_update.winfo_ismapped():
        password_update.pack(pady=5)
        password_update.focus_set()

# Updates the password in the DB once all checks clear
def password_set_update(event=None):
    password_set_label.pack(pady=5)
    service = service_update.get().strip()
    password = password_update.get().strip()
    add_service(current_email, service, current_passkey, password)
    password_set_label.config(text="Password updated")

# Handles functionality when the "Remove service" button is pressed
def enter_service_remove(event=None):
    clear_box()
    main_label.config(text="Enter a service to remove:", font=("Courier", 10))
    if not remove_service_entry.winfo_ismapped():
        remove_service_entry.pack(pady=5)
        remove_service_entry.focus_set()

# Handles functionality for removing the entered service, verifying it exists
def removed_service(event=None):
    service = remove_service_entry.get().strip().lower()
    if not check_service(current_email, service):
        removed_label.pack(pady=5)
        removed_label.config(text="Service not in database")
        return
    remove_service(current_email, service)
    removed_label.config(text=f"Removed passwords for {service.title()}")
    removed_label.pack(pady=5)

# Handles functionality when the "Delete account" button is pressed
def delete_account(event=None):
    clear_box()
    main_label.config(text="This doesn't work yet :)")

# Outputs the list of all services and passwords to the output label in the main menu
def list_all(event=None):
    clear_box()
    list_services_password = list_services(current_email, current_passkey)
    main_label.config(text=list_services_password, font=("Courier", 9))

# Ensures the JSON file is saved once the window is closed
def on_close():
    if current_email and current_passkey:
        user = retrieve_user(current_email)
        write_to_json(user, deleted, current_email)
    root.destroy()

# Set up and size the window
root = tk.Tk()
root.geometry("500x400")

### Frames ###
start_menu = tk.Frame(root, bg="lightblue")
login_menu = tk.Frame(root, bg="lightblue")
reg_menu = tk.Frame(root, bg="lightblue")
main_menu = tk.Frame(root, bg="lightblue")

frames = [start_menu, login_menu, reg_menu, main_menu]

### Start Menu Widgets ###
tk.Label(start_menu, text="Welcome to\nPassword Manager", font=("Courier", 20), fg="darkblue", bg="lightblue").pack(pady=20)
tk.Button(start_menu, text="Login", command=lambda: show_frame(login_menu)).pack(pady=10)
tk.Button(start_menu, text="Register new account", command=lambda: show_frame(reg_menu)).pack(pady=10)


### Login Menu Widgets ###
tk.Label(login_menu, text="Login", font=("Courier", 20), fg="darkblue", bg="lightblue").pack(pady=10)
tk.Button(login_menu, text="Back to Main Menu", command=lambda: show_frame(start_menu)).pack(pady=5)
email_label_login = tk.Label(login_menu, text="Enter email", bg="lightblue", fg="darkblue", font=("Courier", 12))
email_label_login.pack(pady=5)
email_entry_login = tk.Entry(login_menu)
email_entry_login.pack(pady=5)
email_entry_login.bind("<Return>", submit_email_login)

passkey_label_login = tk.Label(login_menu, text="Enter passkey", bg="lightblue", fg="darkblue", font=("Courier", 12))
passkey_entry_login = tk.Entry(login_menu, show = "*")
passkey_entry_login.bind("<Return>", submit_passkey_login)

login_result_label = tk.Label(login_menu, bg="lightblue", fg="darkblue", font=("Courier", 12))

### Register Menu Widgets ###
tk.Label(reg_menu, text="Register new account", font=("Courier", 20), fg="darkblue", bg="lightblue").pack(pady=10)
tk.Button(reg_menu, text="Back to Main Menu", command=lambda: show_frame(start_menu)).pack(pady=5)
email_label_reg = tk.Label(reg_menu, text="Register an email", bg="lightblue", fg="darkblue", font=("Courier", 12))
email_label_reg.pack(pady=5)
email_entry_reg = tk.Entry(reg_menu)
email_entry_reg.pack(pady=5)
email_entry_reg.bind("<Return>", submit_email_reg)

passkey_label_reg = tk.Label(reg_menu, text="Create a passkey", bg="lightblue", fg="darkblue", font=("Courier", 12))
passkey_entry_reg = tk.Entry(reg_menu, show = "*")
passkey_entry_reg.bind("<Return>", submit_passkey_reg)

passkey_label_reg_confirm = tk.Label(reg_menu, text="Confirm passkey", bg="lightblue", fg="darkblue", font=("Courier", 12))
passkey_entry_reg_confirm = tk.Entry(reg_menu, show = "*")
passkey_entry_reg_confirm.bind("<Return>", confirm_passkey)


### Main Menu Widgets ###
tk.Label(main_menu, text="Password Manager", font=("Courier", 20), fg="darkblue", bg="lightblue").pack(pady=10)

### Frame for output box ###
output_frame = tk.Frame(main_menu, bg="lightblue")
output_frame.pack(pady=5)

main_label = tk.Label(output_frame, text="Press a button to start", bg="lightblue", fg="darkblue", font=("Courier", 10))
main_label.pack(pady=5)

service_entry = tk.Entry(output_frame)
service_entry.bind("<Return>", enter_password)

password_label = tk.Label(output_frame, text="Enter password:", bg="lightblue", fg="darkblue", font=("Courier", 10))

password_entry = tk.Entry(output_frame)
password_entry.bind("<Return>", password_set)

service_update = tk.Entry(output_frame)
service_update.bind("<Return>", update_password)

password_update = tk.Entry(output_frame)
password_update.bind("<Return>", password_set_update)

password_set_label = tk.Label(output_frame, bg="lightblue", fg="darkblue", font=("Courier", 10))

remove_service_entry = tk.Entry(output_frame)
remove_service_entry.bind("<Return>", removed_service)

removed_label = tk.Label(output_frame, bg="lightblue", fg="darkblue", font=("Courier", 10))

### Frame for buttons ###
button_frame = tk.Frame(main_menu, bg="lightblue")
button_frame.pack(pady=20)

# Configure 3 columns so centering works
button_frame.columnconfigure(0, weight=1)
button_frame.columnconfigure(1, weight=1)
button_frame.columnconfigure(2, weight=1)

# Top 2x2 grid
tk.Button(button_frame, text="Add service", width=15, command=enter_service)\
    .grid(row=0, column=0, padx=10, pady=10)

tk.Button(button_frame, text="Remove service", width=15, command=enter_service_remove)\
    .grid(row=0, column=2, padx=10, pady=10)

tk.Button(button_frame, text="Update service", width=15, command=update_service)\
    .grid(row=1, column=0, padx=10, pady=10)

tk.Button(button_frame, text="Help", width=15, command=show_help)\
    .grid(row=1, column=2, padx=10, pady=10)

tk.Button(button_frame, text="List services", width=15, command=list_all)\
    .grid(row=2, column=0, padx=3, pady=10)

# Bottom centered button
tk.Button(button_frame, text="Delete account", width=15, command=delete_account)\
    .grid(row=2, column=2, padx=3, pady=10)

### Show initial frame ###
show_frame(start_menu)

root.protocol("WM_DELETE_WINDOW", on_close)

root.mainloop()



