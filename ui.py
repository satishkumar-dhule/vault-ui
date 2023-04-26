import tkinter as tk
import json
from tkinter import ttk
import os,subprocess
from tkinter import messagebox
from vaultlib import *
from tkinter import simpledialog

vault_client=None
secret_details = None
secret_list=None
list_of_paths=None
config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")



# read data from config file and set default values for any missing keys
with open(config_file) as f:
    past_values = json.load(f)
default_keys = ['aws_cred', 'FI', 'vault_role','secrets_path']
for key in default_keys:
    past_values.setdefault(key, [])

# set up tkinter window
root = tk.Tk()
root.geometry('600x300')
root.title('Vault UI')

# create notebook
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# function to add new option to list and config file
def add_option(combobox, value_list, add_button):
    new_option = combobox.get()
    print(combobox, value_list, add_button)
    print(new_option,value_list)
    if new_option not in value_list:
        value_list.append(new_option)
        print(combobox['values'])
        combobox['values'] = ["Enter or select"] + value_list
        with open(config_file, 'w') as f:
            print(past_values)
            json.dump(past_values, f)
        add_button.config(text='\u2714')
        root.after(3000, lambda: add_button.config(text='+'))
    else:
        add_button.config(text='!')
        root.after(3000, lambda: add_button.config(text='+'))

# function to delete an option from the combobox and its corresponding value list
def delete_option(combobox, value_list, delete_button):
    selected_option = combobox.get()
    if selected_option in value_list:
        value_list.remove(selected_option)
        combobox['values'] = ["Enter or select"] + value_list
        with open(config_file, 'w') as f:
            json.dump(past_values, f)
        delete_button.config(text='\u2714')
        root.after(3000, lambda: delete_button.config(text='-'))
        combobox.current(0)
        return f"Successfully deleted {selected_option}"
    else:
        delete_button.config(text='!')
        root.after(3000, lambda: delete_button.config(text='-'))
        return f"{selected_option} not found"

# define function to save all the values in the current tab to the config file
def save_values():
    for combobox, value_list, add_button, delete_button in comboboxes:
        add_option(combobox, value_list, add_button)
        delete_option(combobox, value_list, delete_button)

# create config tab
config_tab = ttk.Frame(notebook,name='config')
notebook.add(config_tab, text='Config')
# create vault tab
vault_tab = ttk.Frame(notebook)
notebook.add(vault_tab, text='Vault')


tab2input={config_tab:['aws_cred', 'FI', 'secrets_path','vault_role']}

def get_parent(item):
    for k,v in tab2input.items():
        if item in v:
            return k
    return -1

# create aws_cred, FI and vault role dropdown menus and buttons
comboboxes = dict({})


comboboxes_frame = ttk.Frame(config_tab)
comboboxes_frame.pack()

for i, key in enumerate(('aws_cred', 'FI', 'vault_role', 'secrets_path')):
    value_list = past_values.get(key,[])
    combobox_frame = ttk.Frame(comboboxes_frame)
    combobox_frame.grid(row=i, column=0, padx=10, pady=10, sticky='w')

    combobox = ttk.Combobox(combobox_frame, values=[f"Enter or select {key}"] + value_list)
    combobox.current(0)
    combobox.grid(row=0, column=0)

    add_button = ttk.Button(combobox_frame, text='+', width=1)
    add_button.grid(row=0, column=1, padx=(5, 0))
    add_button.configure(command=lambda combobox=combobox, value_list=value_list, button=add_button: add_option(combobox, value_list, button))

    delete_button = ttk.Button(combobox_frame, text='-', width=1)
    delete_button.grid(row=0, column=2, padx=(0, 10))
    delete_button.configure(command=lambda combobox=combobox, value_list=value_list, button=delete_button: delete_option(combobox, value_list, button))

    comboboxes[key] = (combobox, value_list)



def show_secrets(path):
    global list_of_paths
    if vault_client is None:
        messagebox.showwarning("Warning", "Generate valid token before executing this action!")
        return
    global secret_list
    secret_list_selected_idx =  0

    if secret_list is not None:
        secret_list_selected_idx=secret_list.winfo_children()[0].current()
        secret_list.destroy()
        
    if secret_details is not None:
        secret_details.destroy()
    secret_list=ttk.Frame(vault_tab)
    secret_list.pack(pady=10)
    secrets = get_secrets_from_vault(vault_client=vault_client, path=path, results=None)
    list_of_paths=secrets
    # Create a new combo box and populate it with the keys from the secrets dictionary
    keys = list(secrets.keys())
    keys_dropdown = ttk.Combobox(secret_list, values=keys, state='readonly', width=60)
    keys_dropdown.pack()
    delete_path_button = ttk.Button(secret_list, text="- Path", command=lambda:confirm_delete(keys_dropdown.get()))
    delete_path_button.pack()
    add_path_button = ttk.Button(secret_list, text="+ Path",command=add_vault_path)
    add_path_button.pack()

    add_kv_button = ttk.Button(secret_list, text="+ KV", command=lambda:add_key_value_pair_to_path(keys_dropdown.get()))
    add_kv_button.pack()
    try:
        keys_dropdown.current(secret_list_selected_idx)
    except:
        pass

    
    # Bind the combobox selection event to a function that displays the selected value
    keys_dropdown.bind("<<ComboboxSelected>>", lambda event: draw_key_value_list(path=keys_dropdown.get(), secrets=secrets))


def confirm_delete(path):
    confirmed = tk.messagebox.askyesno("Confirmation", f"Are you sure you want to delete '{path}' path?")
    if confirmed:
        
        deleted = vault_client.secrets.kv.v2.delete_metadata_and_all_versions(path=trim_vault_path(path),mount_point="kv")
        if deleted:
            tk.messagebox.showinfo("Success", "The Vault path has been deleted.")
            update_status_bar(f'{path} has been deleted successfuly.')
            show_secrets(comboboxes['secrets_path'][0].get())
        else:
            tk.messagebox.showerror("Error", "Error : There was an error deleting the Vault path.")
            update_status_bar(f'We have failed to delete {path}.')


# Create a function to add the Vault path
def add_vault_path():
    root_path=comboboxes['secrets_path'][0].get()
    try:
        
        # Use the simpledialog.askstring method to prompt the user for a Vault path
        path = simpledialog.askstring("Add Vault Path", "Enter the Vault path to add:", parent=root )
        if path is None:
            return
        elif path =="":
            tk.messagebox.showerror("Error", f"Error : Empty paths are not supported.")
            return
        elif not path.startswith(root_path):
            tk.messagebox.showerror("Error", f"Error : Path has to start with {root_path}!")
            return

        
        print(list_of_paths)
        if path in list_of_paths:
            tk.messagebox.showerror("Error", f"Error : '{path}' already exists, duplicates are not supported.")
            return
        # Add the Vault path
        vault_client.secrets.kv.v2.create_or_update_secret(
        path=trim_vault_path(path),mount_point="kv", secret=dict({}))

        # vault_client.secrets.kv.v2.create_or_update_secret_path(trim_vault_path(path), mount_point="kv")
        show_secrets(comboboxes['secrets_path'][0].get())
        tk.messagebox.showinfo("Success", f"The Vault path '{path}'has been added.")


    except Exception as e:
        # Display an error message if the path could not be added
        error_message = "An error occurred while adding the Vault path:\n\n{}".format(str(e))
        tk.messagebox.showerror("Error", error_message)


def update_secret_value(path, key, value, button,vault_client=vault_client):
    print(path, key, value, button)
    try:
        update_secret(vault_client, path, key, value, mount_point="kv")
        button.configure(text='\u2714', state="disabled")
    except Exception as e:
        print(f"{e}")
        button.configure(text="Fail", state="disabled")



def add_key_value_pair_to_path(path):
    
    try:
        # Get the path, key, and value from the user using dialog boxes
        key = simpledialog.askstring('Vault Key', 'Enter the key for the Vault secret:')
        value = simpledialog.askstring('Vault Value', 'Enter the value for the Vault secret:')
        if key == "" or value == "" or key is None or value is None:
            return

        # Get the existing secrets at the path, if any
        existing_secrets = vault_client.secrets.kv.v2.read_secret_version(
            path=trim_vault_path(path),mount_point="kv"
        ).get('data', {}).get('data', {})

        if key in existing_secrets:
            tk.messagebox.showinfo("Fail", f"Key -->{key}<-- already exists, please use update feature for existing keys.")
            return

        # Add the new key-value pair to the existing secrets
        existing_secrets[key] = value

        # Write the updated secrets back to the Vault path
        vault_client.secrets.kv.v2.create_or_update_secret(
            path=trim_vault_path(path),mount_point="kv",
            secret=existing_secrets
        )
        show_secrets(comboboxes['secrets_path'][0].get())
        tk.messagebox.showinfo("Success", f"The Vault path '{path}'has been added.")
        draw_key_value_list(path, list_of_paths)
    except Exception as e:
        # If there was an error, display an error message in a dialog box
        tk.messagebox.showerror('Error', f'Error adding key-value pair to Vault: {e}')


def remove_key_value_pair_to_path(path,key):
    
    try:
        if key == "" or key is None:
            return

        # Get the existing secrets at the path, if any
        existing_secrets = vault_client.secrets.kv.v2.read_secret_version(
            path=trim_vault_path(path),mount_point="kv"
        ).get('data', {}).get('data', {})

        if key not in existing_secrets:
            tk.messagebox.showinfo("Fail", f"Key -->{key}<-- does not exists.")
            return

        # Remove the new key-value pair to the existing secrets
        del existing_secrets[key]

        # Write the updated secrets back to the Vault path
        vault_client.secrets.kv.v2.create_or_update_secret(
            path=trim_vault_path(path),mount_point="kv",
            secret=existing_secrets
        )
        show_secrets(comboboxes['secrets_path'][0].get())
        tk.messagebox.showinfo("Success", f"The key'{key}'has been removed.")
        draw_key_value_list(path, list_of_paths)
    except Exception as e:
        # If there was an error, display an error message in a dialog box
        tk.messagebox.showerror('Error', f'Error removing key-value pair to Vault: {e}')



def make_update_function(button, path, key, entry, vault_client):
    def update():
        button.configure(state="disabled")
        update_secret_value(path, key, entry.get(), button, vault_client=vault_client)
    return update

def make_del_function(path, key):
    def del_kv_from_path_inner():
        confirmed = tk.messagebox.askyesno("Confirmation", f"Are you sure you want to delete key-value '{key}' from '{path}' path?")
        if not confirmed:
            print("Aborted.")
            return
        remove_key_value_pair_to_path(path=path,key=key)
    return del_kv_from_path_inner



def draw_key_value_list(path, secrets):
    global secret_details
    if secret_details is not None:
        secret_details.destroy()
    secret_details = ttk.Frame(vault_tab, borderwidth=1, relief="ridge")
    secret_details.pack(pady=10, padx=10, expand=True, side='top')

    def on_entry_change(event, button):
        if entry.get():
            button.configure(state="normal", text='Update ?')
        else:
            button.configure(state="disabled")

    # path = combo.get()
    kv_pairs = secrets[path]
    if not kv_pairs:
        label = tk.Label(secret_details, text=f"No key-value pairs found at '{path}'")
        label.pack(side='top')
        return

    for k, v in kv_pairs.items():
        print(f"{k} --> {v}")
        style = ttk.Style()
        style.configure('PairFrame.TFrame', borderwidth=0, relief=tk.FLAT)
        # pair_frame = ttk.Frame(secret_details, style='PairFrame.TFrame')
        pair_frame = tk.Frame(master=secret_details, relief=tk.FLAT)
        pair_frame.pack(side='top', fill="x")
        del_kv_button = tk.Button(pair_frame, text="X",  width=1)
        del_kv_button.grid(row=0, column=0, padx=(10, 0), pady=5, sticky="e")

        label = tk.Label(pair_frame, text=k,width=40,anchor='e')
        label.grid(row=0, column=1, padx=(0, 10), sticky="w")

        entry = tk.Entry(pair_frame, width=40)
        entry.insert(0, v)
        entry.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        button = tk.Button(pair_frame, text="Update", state="disabled", width=20)
        button.grid(row=0, column=3, padx=(10, 0), pady=5, sticky="e")

        update_func = make_update_function(button, path, k, entry, vault_client=vault_client)
        button.configure(command=update_func)

        del_func = make_del_function(path, k)
        del_kv_button.configure(command=del_func)


        entry.bind("<KeyRelease>", lambda event, button=button: on_entry_change(event, button))

        pair_frame.grid_columnconfigure(0, weight=1, minsize=0, pad=0)
        pair_frame.grid_columnconfigure(1, weight=1, minsize=0, pad=0)
        pair_frame.grid_columnconfigure(2, weight=1, minsize=0, pad=0)





def generate_vault_token():
    global vault_client
    # Get input values from GUI
    fi = comboboxes['FI'][0].get()
    aws_creds_cmd = comboboxes['aws_cred'][0].get()
    vault_role = comboboxes['vault_role'][0].get()
    # print (fi,aws_creds_cmd,vault_role)

    if not all([fi, aws_creds_cmd, vault_role]):
        messagebox.showwarning("Warning", "Please select FI, AWS credentials, and Vault role!")
        return

    # Set environment variables for Vault
    os.environ['FI'] = fi
    os.environ['AWS_CREDENTIALS_COMMAND'] = aws_creds_cmd
    alt=aws_creds_cmd.split('export ')[1]
    os.environ['AWS_ACCESS_KEY_ID']="=".join(alt.split(" ")[0].split("=")[1:])
    os.environ['AWS_SECRET_ACCESS_KEY']="=".join(alt.split(" ")[1].split("=")[1:])
    os.environ['AWS_SESSION_TOKEN']="=".join(alt.split(" ")[2].split("=")[1:])
    os.environ['VAULT_ROLE'] = vault_role
    os.environ['CFG_ADDR'] = f"https://api.vault-config.top.secrets.{fi}.aws.sfdc.cl:443"
    os.environ['AWS_LOGIN_HEADER'] = f"api.vault.secrets.{fi}.aws.sfdc.cl"
    os.environ['VAULT_ADDR'] = f"https://{os.environ['AWS_LOGIN_HEADER']}"

    try:

        vault_client=get_falcon_vault_client(vault_role,f"https://{os.environ['AWS_LOGIN_HEADER']}","")
    except Exception as e:
        messagebox.showwarning("Error", f"{e}")

    if vault_client is not None:

        messagebox.showinfo("Success", 'Token generated Successfully!')
        show_secrets(comboboxes['secrets_path'][0].get())
    else:

        messagebox.showwarning("Error", f"Token generation Failed!")


# create "Retrieve Token" button
ttk.Button(config_tab, text='Retrieve Token', command=generate_vault_token).pack(pady=10)
# ttk.Button(vault_tab, text='Retrieve KVs', command=lambda:show_secrets(comboboxes['secrets_path'][0].get())).pack(pady=10)
# delete_path_button = tk.Button(vault_tab, text="Delete Vault Path", command=lambda:confirm_delete(secret_list.keys_dropdown.get()))
# delete_path_button.pack()


# create about tab
about_tab = ttk.Frame(notebook)
notebook.add(about_tab, text='About')

# add text to about tab
about_label = ttk.Label(about_tab, text='Vault Secrets manager!.')
about_label.pack(pady=50)


# Create a label for the status bar and set its initial text
status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

# Update the status bar with a new message
def update_status_bar(new_message):
    status_bar.config(text=new_message)

root.mainloop()
