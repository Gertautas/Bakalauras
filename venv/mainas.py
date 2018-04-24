from tkinter import *
import csv
import sys
from tkinter.filedialog import askopenfilename
from collections import defaultdict
import requests
import json
import simplejson
import time
from pathlib import Path
import pathlib
import os


class Application(Frame):

    def __init__ (self, master):
        Frame.__init__(self,master)
        self.grid()
        self.main_window()

    def main_window(self):
            menu = Menu(root)
            root.config(menu=menu)

            subMenu = Menu(menu)
            menu.add_cascade(label="File", menu=subMenu)
            subMenu.add_cascade(label="Scan file", command=lambda: Application.scan_file(self))
            subMenu.add_cascade(label="Import file", command=lambda : Application.choose_file(self))
            subMenu.add_command(label="Exit", command=exit)
            subMenu.add_separator()


            Label(self, text="Pasirinkite stulpelius, kuriuos norite skanuoti: ").grid(row=1,column=0,sticky=W)

            #config checkbutton
            self.config_nr=BooleanVar()
            Checkbutton(self, text= "Config", variable=self.config_nr, command= self.update_text).grid(row=2, column=0,sticky=W)

            #base_Adress checkbutton
            self.Base_adress=BooleanVar()
            Checkbutton(self, text= "BASE_ADDRESS", variable=self.Base_adress, command= self.update_text).grid(row=2, column=3,sticky=W)

            #Memory_sz checkbutton
            self.Memory_sz=BooleanVar()
            Checkbutton(self, text="MEMORY_SIZE", variable=self.Memory_sz, command=self.update_text).grid(row=2, column=8, sticky=W)

            #proc_base_adress checkbutton
            self.proc_base_adress=BooleanVar()
            Checkbutton(self, text= "PROCESS.base.BASE_ADDRESS", variable=self.proc_base_adress, command= self.update_text).grid(row=3, column=0,sticky=W)

            #proc_command_line checkbutton
            self.proc_command_line=BooleanVar()
            Checkbutton(self, text= "PROCESS.base.COMMAND_LINE", variable=self.proc_command_line, command = self.update_text).grid(row=3, column=3, sticky=W)

            #proc_file_path checkbutton
            self.proc_file_path=BooleanVar()
            Checkbutton(self, text="PROCESS.base.FILE_PATH", variable = self.proc_file_path, command = self.update_text).grid(row=3, column=8, sticky=W)

            #proc_image_size checkbutton
            self.proc_image_size = BooleanVar()
            Checkbutton(self, text="PROCESS.base.IMAGE_SIZE", variable=self.proc_image_size,command = self.update_text).grid(row=4, column=0, sticky=W)

            #proc_p_proc_id checkbutton
            self.p_proc_id=BooleanVar()
            Checkbutton(self, text="PROCESS.base.PARENT_PROCESS_ID", variable=self.p_proc_id,command=self.update_text).grid(row=4, column=3, sticky=W)

            #proc_process_id checkbutton
            self.proc_process_id=BooleanVar()
            Checkbutton(self, text="PROCESS.base.PROCESS_ID", variable=self.proc_process_id, command=self.update_text).grid(row=4, column=8, sticky=W)

            #proc_session_id checkbutton
            self.proc_session_id=BooleanVar()
            Checkbutton(self, text="PROCESS.base.SESSION_ID", variable=self.proc_session_id, command=self.update_text).grid(row=5, column=0, sticky=W)

            #proc_threads checkbutton
            self.proc_threads=BooleanVar()
            Checkbutton(self, text="PROCESS.base.THREADS", variable=self.proc_threads, command=self.update_text).grid(row=5, column=3, sticky=W)

            #proc_memory_usage checkbutton
            self.proc_memory_usage=BooleanVar()
            Checkbutton(self, text="PROCESS.hcp.MEMORY_USAGE", variable=self.proc_memory_usage, command=self.update_text).grid(row=5, column=8, sticky=W)

            #T_Stamp checkbutton
            self.T_Stamp=BooleanVar()
            Checkbutton(self, text="TIMESTAMP", variable=self.T_Stamp, command=self.update_text).grid(row=6, column=0, sticky=W)

            #ev_ID checkbutton
            self.ev_ID=BooleanVar()
            Checkbutton(self, text="eventID", variable=self.ev_ID, command=self.update_text).grid(row=6, column=3, sticky=W)

            #ev_type checkbutton
            self.ev_type=BooleanVar()
            Checkbutton(self, text="eventType", variable=self.ev_type, command=self.update_text).grid(row=6, column=8, sticky=W)

            #org checkbutton
            self.org=BooleanVar()
            Checkbutton(self, text="org", variable=self.org, command=self.update_text).grid(row=7, column=0, sticky=W)

            #platforma checkbutton
            self.platforma=BooleanVar()
            Checkbutton(self, text="platforma", variable=self.platforma, command=self.update_text).grid(row=7, column=3, sticky=W)

            #sbnt checkbutton
            self.sbnt=BooleanVar()
            Checkbutton(self, text="subnet", variable=self.sbnt, command=self.update_text).grid(row=7, column=8, sticky=W)

            #t_stamp checkbutton
            self.t_stamp=BooleanVar()
            Checkbutton(self, text="timestamp", variable=self.t_stamp, command=self.update_text).grid(row=8, column=0, sticky=W)

            #UNIQUE_ID checkbutton
            self.UNIQUE_ID=BooleanVar()
            Checkbutton(self, text="uniqueID", variable=self.UNIQUE_ID, command=self.update_text).grid(row=8, column=3, sticky=W)



            #button pradeti skanavima
            scan_button=Button(self, text="Select columns", width=12, command=lambda : Application.write_to_file_selected_columns(self))
            scan_button.grid(row=9, column=5)

            self.text = Text(self, width=35, height=5, wrap=WORD)
            self.text.grid(row=9, column=0, columnspan=2, sticky="nsew")


    def choose_file(self):

        self.text.delete('1.0', END)

        fname = askopenfilename(filetypes=(("Excel log files", "*.csv"),
                                           ("Json files", "*.JSON;*.htm"),
                                           ("All files", "*.*")))

        Label(self, text=fname).grid(row=0, column=0, sticky=W)

        columns = defaultdict(list)
        with open(fname) as f:
            reader = csv.DictReader(f)
            for row in reader:
                for (k, v) in row.items():
                    columns[k].append(v)


        if fname:
            try:

                self.config_nr1 = columns['config']
                self.Base_adress1 = columns['NOTIFICATION_HIDDEN_MODULE.base.BASE_ADDRESS']
                self.Memory_sz1 = columns['NOTIFICATION_HIDDEN_MODULE.base.MEMORY_SIZE']
                self.proc_base_adress1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.BASE_ADDRES']
                self.proc_command_line1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.COMMAND_LINE']
                self.proc_file_path1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.FILE_PATH']
                self.proc_image_size1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.IMAGE_SIZE']
                self.proc_p_proc_id1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.PARENT_PROCESS_ID']
                self.proc_process_id1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.PROCESS_ID']
                self.proc_session_id1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.SESSION_ID']
                self.proc_threads1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.base.THREADS']
                self.proc_memory_usage1 = columns['NOTIFICATION_HIDDEN_MODULE.base.PROCESS.hcp.MEMORY_USAGE']
                self.T_Stamp1 = columns['NOTIFICATION_HIDDEN_MODULE.base.TIMESTAMP']
                self.ev_ID1 = columns['eventId']
                self.ev_type1 = columns['eventType']
                self.org1 = columns['org']
                self.platforma1 = columns['platform']
                self.sbnt1 = columns['subnet']
                self.t_stamp1 = columns['timestamp']
                self.UNIQUE_ID1 = columns['uniqueid']



            except OSError as err:  # <- naked except is a bad idea
                showerror("Open Source File", "Failed to read file\n'%s'" % fname)
                print("klaida cia ---> ".format(err))
        #print(self.Memory_sz1)

    def update_text(self):

        tekstas = ""
        if self.config_nr.get():
            #cn=self.config_nr1
            #cn=','.join(self.config_nr1)
            #tekstas +=cn
            print(self.config_nr1)
            #print(tekstas)
            #print(self.config_nr.get())
            #print(self.Base_adress.get())
        if self.Base_adress.get():
            #ba=','.join(self.Base_adress1)
            #tekstas +=ba
            print(self.Base_adress1)
        if self.Memory_sz.get():
            print(self.Memory_sz1)
        if self.proc_base_adress.get():
            print(self.proc_base_adress1)
        if self.proc_command_line.get():
            print(self.proc_command_line1)
        if self.proc_file_path.get():
            print(self.proc_file_path1)
        if self.proc_image_size.get():
            print(self.proc_image_size1)
        if self.p_proc_id.get():
            print(self.proc_p_proc_id1)
        if self.proc_process_id.get():
            print(self.proc_process_id1)
        if self.proc_session_id.get():
            print(self.proc_process_id1)
        if self.proc_threads.get():
            print(self.proc_threads1)
        if self.proc_memory_usage.get():
            print(self.proc_memory_usage1)
        if self.T_Stamp.get():
            print(self.T_Stamp1)
        if self.ev_ID.get():
            print(self.ev_ID1)
        if self.ev_type.get():
            print(self.ev_type1)
        if self.org.get():
            print(self.org1)
        if self.platforma.get():
            print(self.platforma1)
        if self.sbnt.get():
            print(self.sbnt1)
        if self.t_stamp.get():
            print(self.t_stamp1)
        if self.UNIQUE_ID.get():
            print(self.UNIQUE_ID1)

        #self.result.delete(0.0, END)
        #self.result.insert(0.0, tekstas)

    def scan_file(self):

        self.text.delete('1.0', END)

        self.fileName=askopenfilename(filetypes=(("Txt files", "*.txt"),
                                                ("Json files", "*.JSON"),
                                                ("All files", "*.*")))
        #print(self.fileName)

        url= 'https://www.virustotal.com/vtapi/v2/file/scan'
        params={'apikey' : 'bc8a2e91c61c21839e082d2ae06399b1640c3e211f1e9e12e834fa83faede02a'}
        files = {'file': (self.fileName, open(self.fileName,'rb'))}
        self.response_scan = requests.post(url, files=files, params=params)
        #print(self.response.json())
        self.text.insert(END, "File is scanning. Please wait...  + '\n' ")
        self.scanfile_data = self.response_scan.json()
        self.scanfile_data_permalink = self.scanfile_data['permalink']

        self.text.insert(END,"linkas: " + self.scanfile_data_permalink)


    def write_to_file_selected_columns(self):
        tekstas = ""
        self.f = open('file.txt', 'w')

        if self.config_nr.get()==True:
            cn=self.config_nr1
            cn=','.join(self.config_nr1)
            tekstas +=cn
            self.f.write(tekstas + '\n' + '\n')

        if self.Base_adress.get()==True:
            ba=self.Base_adress1
            simplejson.dump(ba, self.f)
            self.f.write('\n' + '\n')

        if self.Memory_sz.get()==True:
            mz=self.Memory_sz1
            simplejson.dump(mz, self.f)
            self.f.write('\n' + '\n')

        if self.proc_base_adress.get()==True:
            pba=self.proc_base_adress1
            simplejson.dump(pba, self.f)
            self.f.write('\n' + '\n')

        if self.proc_command_line.get()==True:
            pcl=self.proc_command_line1
            simplejson.dump(pcl,self.f)
            self.f.write('\n' + '\n')

        if self.proc_file_path.get()==True:
            pfp=self.proc_file_path1
            simplejson.dump(pfp, self.f)
            self.f.write('\n' + '\n')

        if self.proc_image_size.get()==True:
            piz=self.proc_image_size1
            simplejson.dump(piz, self.f)
            self.f.write('\n' + '\n')

        if self.p_proc_id.get()==True:
            ppi=self.proc_p_proc_id1
            simplejson.dump(ppi, self.f)
            self.f.write('\n' + '\n')

        if self.proc_process_id.get()==True:
            procpi=self.proc_process_id1
            simplejson.dump(procpi, self.f)
            self.f.write('\n' + '\n')

        if self.proc_session_id.get()==True:
            psi=self.proc_session_id1
            simplejson.dump(psi, self.f)
            self.f.write('\n' + '\n')

        if self.proc_threads.get()==True:
            pt=self.proc_threads1
            simplejson.dump(pt, self.f)
            self.f.write('\n' + '\n')

        if self.proc_memory_usage.get()==True:
            pmu=self.proc_memory_usage1
            simplejson.dump(pmu, self.f)
            self.f.write('\n' + '\n')

        if self.T_Stamp.get()==True:
            TS=self.T_Stamp1
            simplejson.dump(TS, self.f)
            self.f.write('\n' + '\n')

        if self.ev_ID.get()==True:
            eID=self.ev_ID1
            simplejson.dump(eID, self.f)
            self.f.write('\n' + '\n')

        if self.ev_type.get()==True:
            et=self.ev_type1
            simplejson.dump(et, self.f)
            self.f.write('\n' + '\n')

        if self.org.get()==True:
            orgas=self.org1
            simplejson.dump(orgas, self.f)
            self.f.write('\n' + '\n')

        if self.platforma.get()==True:
            platf=self.platforma1
            simplejson.dump(platf, self.f)
            self.f.write('\n' + '\n')

        if self.sbnt.get()==True:
            SBNT=self.sbnt1
            simplejson.dump(SBNT, self.f)
            self.f.write('\n' + '\n')

        if self.t_stamp.get()==True:
            ts=self.t_stamp1
            simplejson.dump(ts, self.f)
            self.f.write('\n' + '\n')

        if self.UNIQUE_ID.get()==True:
            UID=self.UNIQUE_ID1
            simplejson.dump(UID, self.f)
            self.f.write('\n' + '\n')

        time.sleep(5)

        self.text.insert(END, "Columns selected." + '\n')

        self.send_button = Button(self, text="Scan file! ", width=12, command= lambda: Application.start_file_scan(self))
        self.send_button.grid(row=9, column=9)

        self.f.close()




    def start_file_scan(self):

        self.text.delete('1.0', END)

        #self.f = open('file.txt', 'w')
        self.p=pathlib.Path('file.txt')
        self.s=str(self.p.absolute())
        self.a=self.s.replace('\\','/')
        #print(self.a)
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': 'bc8a2e91c61c21839e082d2ae06399b1640c3e211f1e9e12e834fa83faede02a'}
        files = {'file': (self.a, open(self.a,'rb'))}
        self.response=requests.post(url, files=files, params=params)
        #print(self.response.json())

        self.text.insert(END, "File is scanning. Please wait... "  + '\n')

        #time.sleep(5)

        self.data = self.response.json()
        #print(self.data)
        self.data_permalink = self.data['permalink']
        #print(self.data_permalink)
        #print('linkas: ' + self.file_scan_permalink)
        self.text.insert(END, 'linkas: ' + self.data_permalink)






root = Tk()
root.title("Bakalauras")
app = Application(root)

app.mainloop()




