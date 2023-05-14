import json
import customtkinter
from customtkinter.windows.widgets.font import CTkFont
import tkinter
import hvac
import time
from tkinter import *
import requests
import ast


class App:
    CONFIG_FILE = "config.json"

    def __init__(self):
        self.toplevel_window = None
        customtkinter.set_appearance_mode("dark")  # Modes: "System" (standard), "Dark", "Light"
        customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

        self.app = customtkinter.CTk()
        self.app.geometry()
        self.app.wm_minsize(width=400, height=300)
        self.app.title("Vault UI")
        self.vault_client=None

        self.main_frame_secrets = customtkinter.CTkFrame(master=self.app)
        self.main_frame_secrets.pack(pady=0, padx=0, expand=True, anchor="center",ipadx=30,ipady=30)

        self.title = customtkinter.CTkLabel(master=self.main_frame_secrets, text="Generate Token".upper(),height=28, font=CTkFont(weight="bold", size=14), fg_color="#3B8ED0")
        self.title.pack(pady=(0, 10), padx=0, ipady=30, fill='both', expand=True)

        self.entries = dict({})
        for label, text in [("AWS Credentials", ""), ("Vault FI", ""), ("Root Path", ""), ("Vault Role", "")]:
            label_this = customtkinter.CTkLabel(master=self.main_frame_secrets, text=label)
            label_this.pack(pady=(10,0), padx=10, anchor="w")
            entry = customtkinter.CTkEntry(master=self.main_frame_secrets, width=500, placeholder_text=text)
            entry.pack(pady=5, padx=10, ipady=8)
            self.entries[label]=entry

        self.btn_generate_token = customtkinter.CTkButton(
            master=self.main_frame_secrets, text="Generate", command=self.on_generate_token
        )
        self.btn_generate_token.pack(pady=30, padx=10, ipady=8)

        self.load_config()

    def generate_token(self):
        pass



    def get_secrets_from_vault(self, vault_client, path, results=None,recursion_depth=0):
        print(path)
        if recursion_depth == 0 and not path.endswith('/'):
            path=path+'/'


        if results is None:
            results = {}
        path_t,mount_point=("/".join(path.split('/')[1:]),path.split('/')[0])
        print(path_t, mount_point)
        if path[-1] == '/':
            try:
                output=vault_client.secrets.kv.v2.list_secrets(path_t, mount_point)
                # print(output)
                keys=output['data']['keys']
                # print(keys)
                for k in keys:
                    self.get_secrets_from_vault(vault_client,f"{path}{k}", results,recursion_depth=recursion_depth+1)
            except Exception as e:
                print(e,path)
                # raise(e)

        else:
            try:
                output=vault_client.secrets.kv.v2.read_secret_version(
                path=path_t, mount_point=mount_point,raise_on_deleted_version=True)
                results[path] = output['data']['data']
            except hvac.exceptions.InvalidPath:
                results[path] = dict({})
        # print(results)
        return results

    def get_falcon_vault_client(self,addr,vault_role,  access_key,secret_key,token):

        # login_header = 'api.vault.secrets.aws-dev2-uswest2.aws.sfdc.cl'
        login_header = addr.split('//')[1]
        for num_tries in range(3):
            client = hvac.Client(url=addr, verify='cacerts.pem')
            if 'giaprod1-usgoveast1' in addr:
                client.auth.aws.iam_login(access_key,
                                        secret_key,
                                        token,
                                        header_value=login_header,
                                        role=vault_role,region='us-gov-east-1',
                                        use_token=True
                                        )
            else:
                client.auth.aws.iam_login(access_key,
                                        secret_key,
                                        token,
                                        header_value=login_header,
                                        role=vault_role,
                                        use_token=True
                                        )
            if client.is_authenticated():
                return client
            time.sleep(num_tries + 1)
        return None

    def show_secrets(self,combo,secrets):

        combo.configure(values=secrets.keys())
        combo.update()



    def draw_kv(self, combo_kv_list, secrets_master, frame_kv_list):

        print(combo_kv_list, secrets_master, frame_kv_list)
        path = combo_kv_list.get().rstrip('/')

        if path not in secrets_master:
            tkinter.messagebox.showinfo("Alert", f"Non-existant Path! {path}.")
            return
        

        self.frame_kv_list.configure( label_text=path)


        frame_set = customtkinter.CTkFrame(master=frame_kv_list)
        frame_kv_list.columnconfigure(0, weight=1)

        
        frame_set.columnconfigure(0, weight=1)
        frame_set.columnconfigure(1, weight=1)
        frame_set.columnconfigure(2, weight=1)
        frame_set.columnconfigure(3, weight=1)

        # customtkinter.CTkLabel(master=frame_set,text=path).grid(row=0,columnspan=4,ipadx=30, ipady=30)


        if self.switch_var.get()=='on':
            print("in switch on")
            try:
                self.add_kv_frame.grid_forget()
                
            except:
                pass
            
            try:
                self.add_kv_frame_json.forget()
                
            except:
                pass


            self.add_kv_frame_json = customtkinter.CTkFrame(master=frame_set)
            self.add_kv_frame_json.grid(row=1,columnspan=4,ipadx=10, ipady=10)


            self.textbox = customtkinter.CTkTextbox(master=self.add_kv_frame_json, width=100000,height=800,corner_radius=0)
            self.textbox.pack(fill="both", expand=True)
            self.textbox.insert("0.0",self.secrets_master[path])


        else:
            print("in switch off")
            try:
                self.add_kv_frame_json.forget()
                
            except:
                pass
            self.add_kv_frame = customtkinter.CTkFrame(master=frame_set)
            self.add_kv_frame.grid(row=1,columnspan=4,ipadx=10, ipady=10)
            customtkinter.CTkLabel(self.add_kv_frame,text="Add KV").pack()
            self.entry_key= customtkinter.CTkEntry(self.add_kv_frame, width=500, placeholder_text="Enter new key here")
            self.entry_value= customtkinter.CTkEntry(self.add_kv_frame,width=500,placeholder_text="Enter new value here")
            self.button_add_kv= customtkinter.CTkButton(self.add_kv_frame,text="+KV")
            self.entry_key.pack( side='left',pady=5, padx=10)
            self.entry_value.pack( side='left',pady=0, padx=1)
            self.button_add_kv.pack( side='left',pady=0, padx=1 )
            self.button_add_kv.configure(command=lambda:self.add_kv(path,self.entry_key,self.entry_value,secrets_master))
            self.entry_value.bind('<Return>', command=lambda event:self.add_kv(path,self.entry_key,self.entry_value,secrets_master))

            def make_del(path,k):
                def inner():
                    print("inner : ",path,k,self.secrets_master)
                    self.del_kv(path,k,self.secrets_master)
                return inner
            
            def make_update(path,k,value_entry,button_update):
                def inner():
                    print("inner : ",path,k)
                    self.update_kv(path,k,value_entry,button_update)
                return inner
            



            def on_entry_change(event, button):
                if entry.get():
                    button.configure(state="normal", text='Update ?')
                else:
                    button.configure(state="disabled")



            for i, (k, v) in enumerate(secrets_master[path].items(),start=4):
                label = customtkinter.CTkLabel(master=frame_set, text=k)
                label.grid(row=i, column=0,sticky='e',padx=8,pady=8)

                entry = customtkinter.CTkEntry(master=frame_set)
                entry.grid(row=i, column=1, sticky='ew',padx=8,pady=8)
                entry.insert(0, v)

                button_update = customtkinter.CTkButton(master=frame_set, text="Update", width=15, state='disabled')
                button_update.grid(row=i, column=2,padx=8,pady=8,sticky='e')

                button_delete = customtkinter.CTkButton(master=frame_set, text="Delete", width=15, hover_color="red")
                button_delete.grid(row=i, column=3,padx=8,pady=8,sticky='w')
                del_func = make_del(path, k)
                button_delete.configure(command=del_func)
                update_func = make_update(path, k,entry,button_update)
                button_update.configure(command=update_func)

                entry.bind("<KeyRelease>", lambda event, button=button_update: on_entry_change(event, button))

        frame_set.grid(row=0, column=0, sticky='nsew',ipadx=30, ipady=30)

    def trim_vault_path(self,path):
        """
        Our vault instance has a custom mount point of kv/. Although the Vault CLI respects the mount point when provided
        as part of the path, the Python HVAC vault client does not. This little function just trims the path transparently.
        """
        if path.startswith("kv/"):
            split_path = path.split("/")
            path = "/".join(split_path[1:])
        return path

    def add_path(self,vault_client,combo_kv_list,secrets_master,frame_kv_list):
        try:
            path=combo_kv_list.get().rstrip('/')
            if path in self.secrets_master :
                tkinter.messagebox.showinfo("Alert", "Duplicate!")
                return

            vault_client.secrets.kv.v2.create_or_update_secret(
            path=self.trim_vault_path(path),mount_point="kv", secret=dict({}))
            secrets_master[combo_kv_list.get()]={}
            combo_kv_list.configure(values=secrets_master.keys())
            combo_kv_list.update()
            # tkinter.messagebox.showinfo("Success", "The Vault path has been added.")
            self.button_add_path.configure(text='\u2714')
            self.app.after(3000, lambda: self.button_add_path.configure(text='+'))
            self.draw_kv(self.combo_kv_list, secrets_master, self.frame_kv_list)

            
        except Exception as e:
            print(e)
    

    def del_path(self,vault_client,combo_kv_list,secrets_master,frame_kv_list):
        path=combo_kv_list.get()
        confirmed = tkinter.messagebox.askyesno("Confirmation", f"Are you sure you want to delete '{path}' path?")
        if confirmed:         
            # deleted = vault_client.secrets.kv.v2.delete_metadata_and_all_versions(path=self.trim_vault_path(path),mount_point="kv")

            # Set the URL of your Vault server
            vault_url = self.vault_addr

            # Set the Vault token for authentication
            vault_token = vault_client.token

            # Set the path of the subpath you want to delete (relative to the root path)
            subpath = path

            # Construct the URL for deleting the subpath
            delete_url = f"{vault_url}/v1/{subpath}"

            # Set the headers with the Vault token
            headers = {
                'X-Vault-Request': 'true',
                "X-Vault-Token": vault_token,
            }

            # Send the DELETE request to delete the subpath
            response = requests.delete(delete_url, headers=headers,verify='cacerts.pem')
            print(response.text)

            
            if response.status_code == 204:
                # tkinter.messagebox.showinfo("Success", "The Vault path has been deleted.")
                del(secrets_master[combo_kv_list.get()])
                combo_kv_list.configure(values=secrets_master.keys())
                combo_kv_list.update()
                combo_kv_list.set('***Deleted***')
                self.button_remove_path.configure(text='\u2714')
                self.app.after(3000, lambda: self.button_remove_path.configure(text=' - '))
            else:
                tkinter.messagebox.showerror("Error", "Error : There was an error deleting the Vault path.")




    def add_kv(self,path,key,value,secrets_master):
        vault_client=self.client

        
        try:
            
            # Get the existing secrets at the path, if any
            existing_secrets = secrets_master[path]
            print("before:",secrets_master)



            key=key.get()
            value=value.get()
            if key in existing_secrets:
                tkinter.messagebox.showinfo("Fail", f"Key -->{key}<-- already exists, please use update feature for existing keys.")
                return
            if key == "":
                tkinter.messagebox.showinfo("Fail", f"Blank key not allowed!")
                return

            
            # Add the new key-value pair to the existing secrets
            existing_secrets[key] = value
            self.secrets_master[path]=existing_secrets
            print("after:",secrets_master)

            # Write the updated secrets back to the Vault path
            vault_client.secrets.kv.v2.create_or_update_secret(
                path=self.trim_vault_path(path),mount_point="kv",
                secret=existing_secrets
            )

            self.draw_kv(self.combo_kv_list, secrets_master, self.frame_kv_list)

        
        except Exception as e:
            # If there was an error, display an error message in a dialog box
            tkinter.messagebox.showerror('Error', f'Error adding key-value pair to Vault: {e}')
        

    def del_kv(self,path,key,secrets_master):
        vault_client=self.client
        
        try:
            
            # Get the existing secrets at the path, if any
            existing_secrets = secrets_master[path]
            print("before:",secrets_master)

            # Add the new key-value pair to the existing secrets
            del(existing_secrets[key])
            self.secrets_master[path]=existing_secrets
            print("after:",secrets_master)

            # Write the updated secrets back to the Vault path
            vault_client.secrets.kv.v2.create_or_update_secret(
                path=self.trim_vault_path(path),mount_point="kv",
                secret=existing_secrets
            )

            self.draw_kv(self.combo_kv_list, secrets_master, self.frame_kv_list)


        except Exception as e:
            # If there was an error, display an error message in a dialog box
            tkinter.messagebox.showerror('Error', f'Error deleting key-value pair to Vault: {e}')

    def update_kv(self,path,key,value_entry,update_button):
        vault_client=self.client
        
        try:          
            # Get the existing secrets at the path, if any
            existing_secrets = self.secrets_master[path]
            value=value_entry.get()
            print("before:",self.secrets_master, f"k={key} v={value} path={path}")

            # Add the new key-value pair to the existing secrets
            existing_secrets[key]=value
            self.secrets_master[path]=existing_secrets
            print("after:",self.secrets_master)

            # Write the updated secrets back to the Vault path
            vault_client.secrets.kv.v2.create_or_update_secret(
                path=self.trim_vault_path(path),mount_point="kv",
                secret=existing_secrets
            )

            # self.draw_kv(self.combo_kv_list, self.secrets_master, self.frame_kv_list)
            update_button.configure(text='\u2714', state="disabled")


        except Exception as e:
            # If there was an error, display an error message in a dialog box
            tkinter.messagebox.showerror('Error', f'Error updating key-value pair to Vault: {e}')
    



    def show_json(self, vault_client, combo_kv_list):
        path = combo_kv_list.get()
        json_data = self.secrets_master[path]

        if self.toplevel_window is None or not self.toplevel_window.winfo_exists():
            self.toplevel_window = ToplevelWindow(self.app)  # create window if its None or destroyed
            customtkinter.CTkLabel(master=self.toplevel_window,text=path).pack()


            self.textbox = customtkinter.CTkTextbox(master=self.toplevel_window, width=400, corner_radius=0)
            self.textbox.pack(fill="both", expand=True)
            self.textbox.insert("0.0", json_data)
        else:
            self.toplevel_window.focus()  # if window exists focus it






    def on_generate_token(self):
        # Get input values and do something
        input_values = [entry.get() for entry in self.entries.values()]
        # print("Input values:", input_values)

        print(self.entries)
        aws_creds_cmd=self.entries.get("AWS Credentials").get()
        print(aws_creds_cmd)

        alt=aws_creds_cmd.split('export ')[1]
        access_key="=".join(alt.split(" ")[0].split("=")[1:])
        secret_key="=".join(alt.split(" ")[1].split("=")[1:])
        token="=".join(alt.split(" ")[2].split("=")[1:])
        falcon_instance= self.entries.get("Vault FI").get()
        vault_role=self.entries.get("Vault Role").get()
        root_path=self.entries.get("Root Path").get()
        # config_addr = f"https://api.vault-config.top.secrets.{falcon_instance}.aws.sfdc.cl:443"
        login_header = f"api.vault.secrets.{falcon_instance}.aws.sfdc.cl"
        self.vault_addr = f"https://{login_header}"
        self.FI=falcon_instance
        self.root_path=root_path

        try:
            self.client=self.get_falcon_vault_client(addr=self.vault_addr,vault_role=vault_role,  access_key=access_key,secret_key=secret_key,token=token)
            self.secrets_master=self.get_secrets_from_vault(vault_client=self.client, path=root_path)
        except Exception as e:
            tkinter.messagebox.showerror('Error', f'Error generating token : {e}')

        print(self.secrets_master)
        print(self.client.token)


        # Save input values to config file
        self.save_config(input_values)
            # Create a new frame for the new page
        self.frame_2 = customtkinter.CTkFrame(master=self.app,width=1000)
        

        self.frame_2.pack(pady=0, padx=0, fill='both', expand=True, anchor="w",ipadx=30,ipady=30)

        # Add widgets to the new frame for the new page
        self.new_title = customtkinter.CTkLabel(master=self.frame_2, text=f"FI: {self.FI} ROOT: {self.root_path}".upper(), height=28, font=CTkFont(weight="bold", size=14), fg_color="#3B8ED0")
        self.new_title.pack(pady=(0, 10), padx=0, ipady=30, fill='both',anchor="n")



        # Hide the current frame
        self.main_frame_secrets.pack_forget()
        self.frame_path_list_and_buttons = customtkinter.CTkFrame(master=self.frame_2)
        self.frame_path_list_and_buttons.pack(pady=0, padx=0, fill='y',ipady=30,ipadx=30)
        self.combo_kv_list = customtkinter.CTkComboBox(master=self.frame_path_list_and_buttons, values=list(self.secrets_master.keys()), width=500)
        self.combo_kv_list.pack(side='left',pady=5, padx=10)
        self.button_get_kv = customtkinter.CTkButton(master=self.frame_path_list_and_buttons, text="Get KV's",width=3)
        self.button_get_kv.pack( side='left',pady=0, padx=1)

        self.button_add_path = customtkinter.CTkButton(master=self.frame_path_list_and_buttons, text=" + ",width=3)
        self.button_add_path.pack( side='left',pady=0, padx=1)
        self.button_remove_path = customtkinter.CTkButton(master=self.frame_path_list_and_buttons,text=" - ",width=3,hover_color="red")
        self.button_remove_path.pack(side='left',pady=0, padx=1)
        # self.button_show_json = customtkinter.CTkButton(master=self.frame_path_list_and_buttons,text=" JSON ",width=3,hover_color="blue")
        # self.button_show_json.pack(side='left',pady=0, padx=1)

        self.frame_kv_list = customtkinter.CTkScrollableFrame(master=self.frame_2)
        self.frame_kv_list.pack(pady=10, padx=10, fill='both', expand=True, anchor="n",ipadx=30, ipady=30)
        self.button_get_kv.configure(command=lambda :self.draw_kv(self.combo_kv_list,self.secrets_master,self.frame_kv_list))
        self.button_add_path.configure(command=lambda :self.add_path( self.client,  self.combo_kv_list,self.secrets_master,self.frame_kv_list))
        self.button_remove_path.configure(command=lambda :self.del_path( self.client,  self.combo_kv_list,self.secrets_master,self.frame_kv_list))
        self.combo_kv_list.bind('<Return>', command=lambda event:self.draw_kv(self.combo_kv_list,self.secrets_master,self.frame_kv_list))
        # self.button_show_json.configure(command=lambda :self.show_json( self.vault_client,self.combo_kv_list))


        

        self.switch_var = customtkinter.StringVar(value="on")

        def switch_event():
            print("switch toggled, current value:", self.switch_var.get())
            self.draw_kv(self.combo_kv_list, self.secrets_master, self.frame_kv_list)
           

        switch_1 = customtkinter.CTkSwitch(master=self.frame_path_list_and_buttons, text="JSON", command=switch_event,
                                        variable=self.switch_var, onvalue="on", offvalue="off")
        switch_1.pack(side='left',pady=0, padx=20)


    def load_config(self):
        try:
            with open(self.CONFIG_FILE) as f:
                config = json.load(f)
            for entry, value in zip(self.entries.values(), config):
                entry.insert(0, value)
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # Ignore if file doesn't exist or is invalid

    def save_config(self, input_values):
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(input_values, f)

    def run(self):
        self.app.mainloop()


app = App()
app.run()
