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
import tkinter as tk
import re
from tkinter import messagebox



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
            subMenu.add_cascade(label="Test")
            subMenu.add_command(label="Exit", command=exit)
            subMenu.add_separator()

            self.API_KEY = '0abb42dfe1d1103b87eb501f5a248380581ea03289f0b2bc165be458d8cef93e'
            self.f = pathlib.Path('file.txt')
            self.f_ab = "";

            if os.path.exists(self.f):
                os.remove(self.f)


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
            scan_button.grid(row=9, column=2)

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

                self.f = open('file.txt', 'w')
                self.ff = pathlib.Path('file.txt')
                self.f_a =str(self.ff.absolute())
                self.f_ab = self.f_a.replace('\\','/')
                print(self.f_ab)

            except OSError as err:  # <- naked except is a bad idea
                showerror("Open Source File", "Failed to read file\n'%s'" % fname)
                print("klaida cia ---> ".format(err))
        #print(self.Memory_sz1)

    def update_text(self):

        if self.config_nr.get():
            print(self.config_nr1)
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
        params={'apikey' : self.API_KEY}
        files = {'file': (self.fileName, open(self.fileName,'rb'))}
        self.response_scan = requests.post(url, files=files, params=params)
        print(self.response_scan.json())
        self.text.insert(END, "File is scanning. Please wait... " + '\n')
        self.data = self.response_scan.json()
        self.scanfile_data_permalink = self.data['permalink']
        self.scan_id_start_file_Scan = self.data['scan_id']
        self.resource_start_file_Scan = self.data['resource']


        self.text.insert(END,"linkas: " + self.scanfile_data_permalink)

        self.info_button1 = Button(self, text="Detailed info ", width=12, command=lambda: Application.test(self))
        self.info_button1.grid(row=9, column=8)




    def write_to_file_selected_columns(self):
        tekstas = "";

        print(self.f)
        if os.path.isfile(self.f_ab):

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



            self.text.insert(END, "Columns selected." + '\n')

            self.send_button = Button(self, text="Scan file! ", width=12,
                                      command=lambda: Application.start_file_scan(self))
            self.send_button.grid(row=9, column=3)
            self.f.close()

        else:
            messagebox.showerror("Error", "Import file first!")


    def start_file_scan(self):

        self.text.delete('1.0', END)

        if os.path.isfile(self.f_ab):
            try:
                self.hashes = re.findall(r"([a-fA-F\d]{32})", open(self.p).read().lower())
                print(self.hashes)

            except OSError as err:  # <- naked except is a bad idea
                showerror("Something went wrong")
                print("klaida cia ---> ".format(err))

        self.text.insert(END, "File is scanning. Please wait... "  + '\n')

        #time.sleep(5)

        self.data = self.response.json()
        #print(self.data)
        self.data_permalink_start_file_Scan = self.data['permalink']
        self.scan_id_start_file_Scan=self.data['scan_id']
        self.resource_start_file_Scan=self.data['resource']
        #print(self.data_permalink)
        #print('linkas: ' + self.file_scan_permalink)
        self.text.insert(END, 'linkas: ' + self.data_permalink_start_file_Scan)

        self.info_button1 = Button(self, text="Detailed info ", width=12, command = lambda : Application.test(self))
        self.info_button1.grid(row=9, column=8)

        root.mainloop()

    def test(self):

        self.root2 = tk.Tk()

        params = {'apikey': self.API_KEY, 'resource': self.resource_start_file_Scan,
                  'scan_id': self.scan_id_start_file_Scan}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip, My Python request library example client or username"
        }

        self.response_test = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params,
                                          headers=headers)
        self.test_json_respose = self.response_test.json()
        # print(self.test_json_respose)

        self.response_antivirus_programs = [
            'Bkav',
            'MicroWorld-eScan',
            'nProtect',
            'CMC',
            'CAT-QuickHeal',
            'McAfee',
            'MalwareBytes',
            'VIPRE',
            'SUPERAntiSpyware',
            'TheHacker',
            'K7GW',
            'K7AntiVirus',
            'Baidu',
            'Babable',
            'F-Prot',
            'Symantec',
            'ESET-NOD32',
            'TrendMicro-HouseCall',
            'Avast',
            'ClamAV',
            'Kaspersky',
            'BitDefender',
            'NANO-Antivirus',
            'ViRobot',
            'Tencent',
            'Ad-Aware',
            'Emsisoft',
            'Comodo',
            'F-Secure',
            'DrWeb',
            'Zillya',
            'TrendMicro',
            'McAfee-GW-Edition',
            'Sophos',
            'Paloalto',
            'Cyren',
            'Jiangmin',
            'Webroot',
            'Avira',
            'Fortinet',
            'Antiy-AVL',
            'Kingsoft',
            'Arcabit',
            'AegisLab',
            'AhnLab-V3',
            'ZoneAlarm',
            'Avast-Mobile',
            'Microsoft',
            'TotalDefense',
            'ALYac',
            'AVware',
            'VBA32',
            'Zoner',
            'Rising',
            'Yandex',
            'Ikarus',
            'GData',
            'AVG',
            'PANDA',
            'Qihoo-360',
        ]

        self.variable = StringVar(self.root2)
        self.variable.set(self.response_antivirus_programs[0])

        self.w = OptionMenu(self.root2, self.variable, *self.response_antivirus_programs)
        self.w.pack()

        self.root2.title("Detailed info")
        self.root2.geometry("700x200")
        self.detailed_text = Text(self.root2, heigh=5, width=80)
        self.detailed_text.pack()
        self.detailed_text.insert(END, 'Select Antivirus program from the list')

        self.detailed_button = Button(self.root2, text="Info", command=lambda: Application.detailed_info_filter(self))
        self.detailed_button.pack()

    def detailed_info_filter(self):

        self.detailed_text.delete('1.0', END)

        if self.variable.get() == 'Bkav':
            self.bkav = self.test_json_respose['scans']['Bkav']
            # print(self.bkav)
            self.detailed_text.insert(END, self.bkav)

        if self.variable.get() == 'MicroWorld-eScan':
            self.micro_World_escan = self.test_json_respose['scans']['MicroWorld-eScan']
            self.detailed_text.insert(END, self.micro_World_escan)

        if self.variable.get() == 'nProtect':
            self.nprotect = self.test_json_respose['scans']['nProtect']
            self.detailed_text.insert(END, self.nprotect)

        if self.variable.get() == 'CMC':
            self.cmc = self.test_json_respose['scans']['CMC']
            self.detailed_text.insert(END, self.cmc)

        if self.variable.get() == 'CAT-QuickHeal':
            self.cat_quickheal = self.test_json_respose['scans']['CAT-QuickHeal']
            self.detailed_text.insert(END, self.cat_quickheal)

        if self.variable.get() == 'McAfee':
            self.mcafee = self.test_json_respose['scans']['McAfee']
            self.detailed_text.insert(END, self.mcafee)

        if self.variable.get() == 'Malwarebytes':
            self.malwarebytes = self.test_json_respose['scans']['Malwarebytes']
            self.detailed_text.insert(END, self.malwarebytes)

        if self.variable.get() == 'VIPRE':
            self.vipre = self.test_json_respose['scans']['VIPRE']
            self.detailed_text.insert(END, self.vipre)

        if self.variable.get() == 'SUPERAntiSpyware':
            self.super_anti_spyware = self.test_json_respose['scans']['SUPERAntiSpyware']
            self.detailed_text.insert(END, self.super_anti_spyware)

        if self.variable.get() == 'TheHacker':
            self.thehacker = self.test_json_respose['scans']['TheHacker']
            self.detailed_text.insert(END, self.thehacker)

        if self.variable.get() == 'K7GW':
            self.k7gw = self.test_json_respose['scans']['K7GW']
            self.detailed_text.insert(END, self.k7gw)

        if self.variable.get() == 'K7AntiVirus':
            self.k7antivirus = self.test_json_respose['scans']['K7AntiVirus']
            self.detailed_text.insert(END, self.k7antivirus)

        if self.variable.get() == 'Baidu':
            self.baidu = self.test_json_respose['scans']['Baidu']
            self.detailed_text.insert(END, self.baidu)

        if self.variable.get() == 'Babable':
            self.babable = self.test_json_respose['scans']['Babable']
            self.detailed_text.insert(END, self.babable)

        if self.variable.get() == 'F-Prot':
            self.fprot = self.test_json_respose['scans']['F-Prot']
            self.detailed_text.insert(END, self.fprot)

        if self.variable.get() == 'Symantec':
            self.symantec = self.test_json_respose['scans']['Symantec']
            self.detailed_text.insert(END, self.symantec)

        if self.variable.get() == 'ESET-NOD32':
            self.eset_nod32 = self.test_json_respose['scans']['ESET-NOD32']
            self.detailed_text.insert(END, self.eset_nod32)

        if self.variable.get() == 'TrendMicro-HouseCall':
            self.trencmicro_housecall = self.test_json_respose['scans']['TrendMicro-HouseCall']
            self.detailed_text.insert(END, self.trencmicro_housecall)

        if self.variable.get() == 'Avast':
            self.avast = self.test_json_respose['scans']['Avast']
            self.detailed_text.insert(END, self.avast)

        if self.variable.get() == 'ClamAV':
            self.clamav = self.test_json_respose['scans']['ClamAV']
            self.detailed_text.insert(END, self.clamav)

        if self.variable.get() == 'Kaspersky':
            self.kaspersky = self.test_json_respose['scans']['Kaspersky']
            self.detailed_text.insert(END, self.kaspersky)

        if self.variable.get() == 'BitDefender':
            self.bitdefender = self.test_json_respose['scans']['BitDefender']
            self.detailed_text.insert(END, self.bitdefender)

        if self.variable.get() == 'NANO-Antivirus':
            self.nano_antivirus = self.test_json_respose['scans']['NANO-Antivirus']
            self.detailed_text.insert(END, self.nano_antivirus)

        if self.variable.get() == 'ViRobot':
            self.virobot = self.test_json_respose['scans']['ViRobot']
            self.detailed_text.insert(END, self.virobot)

        if self.variable.get() == 'Tencent':
            self.tencent = self.test_json_respose['scans']['Tencent']
            self.detailed_text.insert(END, self.tencent)

        if self.variable.get() == 'Ad-Aware':
            self.adaware = self.test_json_respose['scans']['Ad-Aware']
            self.detailed_text.insert(END, self.adaware)

        if self.variable.get() == 'Emsisoft':
            self.emsisoft = self.test_json_respose['scans']['Emsisoft']
            self.detailed_text.insert(END, self.emsisoft)

        if self.variable.get() == 'Comodo':
            self.comodo = self.test_json_respose['scans']['Comodo']
            self.detailed_text.insert(END, self.comodo)

        if self.variable.get() == 'F-Secure':
            self.f_Secure = self.test_json_respose['scans']['F-Secure']
            self.detailed_text.insert(END, self.f_Secure)

        if self.variable.get() == 'DrWeb':
            self.drweb = self.test_json_respose['scans']['DrWeb']
            self.detailed_text.insert(END, self.drweb)

        if self.variable.get() == 'Zillya':
            self.zillya = self.test_json_respose['scans']['Zillya']
            self.detailed_text.insert(END, self.zillya)

        if self.variable.get() == 'TrendMicro':
            self.trendmicro = self.test_json_respose['scans']['TrendMicro']
            self.detailed_text.insert(END, self.trendmicro)

        if self.variable.get() == 'McAfee-GW-Edition':
            self.mcafee_gw_edition = self.test_json_respose['scans']['McAfee-GW-Edition']
            self.detailed_text.insert(END, self.mcafee_gw_edition)

        if self.variable.get() == 'Sophos':
            self.sophos = self.test_json_respose['scans']['Sophos']
            self.detailed_text.insert(END, self.sophos)

        if self.variable.get() == 'Paloalto':
            self.paloalto = self.test_json_respose['scans']['Paloalto']
            self.detailed_text.insert(END, self.paloalto)

        if self.variable.get() == 'Cyren':
            self.cyren = self.test_json_respose['scans']['Cyren']
            self.detailed_text.insert(END, self.cyren)

        if self.variable.get() == 'Jiangmin':
            self.jiangmin = self.test_json_respose['scans']['Jiangmin']
            self.detailed_text.insert(END, self.jiangmin)

        if self.variable.get() == 'Webroot':
            self.webroot = self.test_json_respose['scans']['Webroot']
            self.detailed_text.insert(END, self.webroot)

        if self.variable.get() == 'Avira':
            self.avira = self.test_json_respose['scans']['Avira']
            self.detailed_text.insert(END, self.avira)

        if self.variable.get() == 'Fortinet':
            self.fortinet = self.test_json_respose['scans']['Fortinet']
            self.detailed_text.insert(END, self.fortinet)

        if self.variable.get() == 'Antiy-AVL':
            self.antiy_avl = self.test_json_respose['scans']['Antiy-AVL']
            self.detailed_text.insert(END, self.antiy_avl)

        if self.variable.get() == 'Kingsoft':
            self.kingsoft = self.test_json_respose['scans']['Kingsoft']
            self.detailed_text.insert(END, self.kingsoft)

        if self.variable.get() == 'Arcabit':
            self.arcabit = self.test_json_respose['scans']['Arcabit']
            self.detailed_text.insert(END, self.arcabit)

        if self.variable.get() == 'AegisLab':
            self.aegislab = self.test_json_respose['scans']['AegisLab']
            self.detailed_text.insert(END, self.aegislab)

        if self.variable.get() == 'AhnLab-V3':
            self.ahnlab_v3 = self.test_json_respose['scans']['AhnLab-V3']
            self.detailed_text.insert(END, self.ahnlab_v3)

        if self.variable.get() == 'ZoneAlarm':
            self.zonealarm = self.test_json_respose['scans']['ZoneAlarm']
            self.detailed_text.insert(END, self.zonealarm)

        if self.variable.get() == 'Avast-Mobile':
            self.avast_mobile = self.test_json_respose['scans']['Avast-Mobile']
            self.detailed_text.insert(END, self.avast_mobile)

        if self.variable.get() == 'Microsoft':
            self.microsoft = self.test_json_respose['scans']['Microsoft']
            self.detailed_text.insert(END, self.microsoft)

        if self.variable.get() == 'TotalDefense':
            self.totaldefense = self.test_json_respose['scans']['TotalDefense']
            self.detailed_text.insert(END, self.totaldefense)

        if self.variable.get() == 'ALYac':
            self.alyac = self.test_json_respose['scans']['ALYac']
            self.detailed_text.insert(END, self.alyac)

        if self.variable.get() == 'AVware':
            self.avware = self.test_json_respose['scans']['AVware']
            self.detailed_text.insert(END, self.avware)

        if self.variable.get() == 'VBA32':
            self.vba32 = self.test_json_respose['scans']['VBA32']
            self.detailed_text.insert(END, self.vba32)

        if self.variable.get() == 'Zoner':
            self.zoner = self.test_json_respose['scans']['Zoner']
            self.detailed_text.insert(END, self.zoner)

        if self.variable.get() == 'Rising':
            self.rising = self.test_json_respose['scans']['Rising']
            self.detailed_text.insert(END, self.rising)

        if self.variable.get() == 'Yandex':
            self.yandex = self.test_json_respose['scans']['Yandex']
            self.detailed_text.insert(END, self.yandex)

        if self.variable.get() == 'Ikarus':
            self.ikarus = self.test_json_respose['scans']['Ikarus']
            self.detailed_text.insert(END, self.ikarus)

        if self.variable.get() == 'GData':
            self.gdata = self.test_json_respose['scans']['GData']
            self.detailed_text.insert(END, self.gdata)

        if self.variable.get() == 'AVG':
            self.avg = self.test_json_respose['scans']['AVG']
            self.detailed_text.insert(END, self.avg)

        if self.variable.get() == 'Panda':
            self.panda = self.test_json_respose['scans']['Panda']
            self.detailed_text.insert(END, self.panda)

        if self.variable.get() == 'Qihoo-360':
            self.qihoo_360 = self.test_json_respose['scans']['Qihoo-360']
            self.detailed_text.insert(END, self.qihoo_360)


root = Tk()
root.title("Bakalauras")
app = Application(root)

app.mainloop()




