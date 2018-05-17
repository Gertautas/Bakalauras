from tkinter import *
from tkinter.filedialog import askopenfilename
import csv
from collections import defaultdict
import time
from tkinter import messagebox
import json
import pathlib
import os
import requests
import hashlib
import re
import pprint



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
        subMenu.add_command(label="Exit", command=exit)
        subMenu.add_separator()

        self.virushare = 'VirusShare_'
        self.API_KEY = '0abb42dfe1d1103b87eb501f5a248380581ea03289f0b2bc165be458d8cef93e'
        self.f = pathlib.Path('file.txt')
        self.f_ab = "";
        self.b = IntVar()
        self.dynamic_check = []
        self.csv_info = []
        self.excel = pathlib.Path('virustotal.csv')
        self.regex = re.compile(r"([a-fA-F\d]{32})")

        if os.path.exists(self.f):
            os.remove(self.f)

        if os.path.exists(self.excel):
            os.remove(self.excel)



        Label(self, text="Import csv file: ").grid(row=1, column=0, sticky=W)

        self.open_csv_button = Button(self, text ="Browse", width=16, command = lambda : Application.open_csv_file(self))
        self.open_csv_button.grid(row=2, column = 0, sticky = W)
        Label(self, text = "").grid(row=3, column = 0, sticky = W)
        Label(self,text = "Enter domain to scan: ").grid(row = 4, column = 0, sticky = W)
        self.domain_text = Text(self, height = 1, width = 25)
        self.domain_text.grid(row=5, column = 0, sticky = W)
        self.domain_scan_button=Button(self, text = "Scan domain! ", width = 16, command = lambda :Application.scan_domain_response(self))
        self.domain_scan_button.grid(row = 7, column = 0, sticky = W)
        Label(self, text = "").grid(row =8, column = 0, sticky=W)
        Label(self, text = "Information about a single Hash code: ").grid(row = 9, column = 0, sticky = W)
        self.single_hash = Text(self, height = 1, width = 25)
        self.single_hash.grid(row = 10, column = 0, sticky = W)
        self.single_hash_button = Button(self, text = "Get hash information! ", width = 16,command = lambda : Application.get_hash_information(self))
        self.single_hash_button.grid(row = 11, column = 0, sticky = W)
        Label(self, text = "").grid(row = 12, column = 0, sticky = W)
        Label(self,text = "Scan file for viruses: "). grid(row = 13, column = 0, sticky = W)
        self.scan_file_button =Button(self, text = "Import file", width = 16, command = lambda : Application.scan_file(self))
        self.scan_file_button.grid(row = 14, column = 0, sticky = W)
        Label(self, text="").grid(row=15, column=0, sticky=W)
        self.text = Text(self, height = 15,width=80)
        self.text.grid(row =16, column = 2)


    def scan_file(self):

        self.fileName = askopenfilename(filetypes=(("Txt files", "*.txt"),
                                                   ("Json files", "*.JSON"),
                                                   ("All files", "*.*")))
        # print(self.fileName)

        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.API_KEY}
        files = {'file': (self.fileName, open(self.fileName, 'rb'))}
        self.response_scan = requests.post(url, files=files, params=params)
        #print(self.response_scan.json())
        self.text.insert(END, "File is scanning. Please wait... " + '\n')
        self.data = self.response_scan.json()
        self.scanfile_data_permalink = self.data['permalink']
        self.scanfile_verbose_msg = self.data['verbose_msg']

        #print(self.data)

        self.text.insert(END, self.scanfile_verbose_msg + '\n')
        self.text.insert(END, "linkas: " + '\n' + self.scanfile_data_permalink + '\n')
        self.text.insert(END, '\n')


    def get_hash_information(self):

        if self.regex.search(self.single_hash.get('1.0', 'end-1c')):

            self.hash_information = self.single_hash.get('1.0', 'end-1c')

            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': self.API_KEY, 'resource': self.hash_information}

            response = requests.get(url, params = params)

            self.hash_information_json = response.json()

            self.positives = self.hash_information_json['positives']
            self.total = self.hash_information_json['total']
            self.mcafee = self.hash_information_json['scans']['McAfee']

            self.text.insert(END, 'Hash ' + self.hash_information + ' info: ' + '\n')
            self.text.insert(END, 'Positive scans: ' + str(self.positives) + '\n')
            self.text.insert(END, 'Total scan: ' + str(self.total) + '\n')
            self.text.insert(END, self.mcafee)
            self.text.insert(END, '\n' + '\n')

            self.root5 = Tk()
            self.root5.title("All info about hash")
            self.root5.geometry("700x500")



        else:
            messagebox.showerror("Error", "Insert a hash! ")



    def write_hashes_to_txt(self):

        if self.b.get() == True:

            self.root3 = Tk()

            self.root3.title("Detailed info")
            self.root3.geometry("700x200")
            self.detailed_hashes_text = Text(self.root3, heigh=10, width=80)
            self.detailed_hashes_text.pack()

            self.detailed_hashes_text.insert(END, 'Hashes found: ' + '\n')
            self.detailed_hashes_text.insert(END, '\n'.join(self.hashes))

            self.scan_hashes = Button(self.root3, text = "Scan hashes", width = 12, command = lambda : Application.scan_hashes(self))
            self.scan_hashes.pack()


        else:
            messagebox.showerror("Error", "Select checkboxes first! ")


        #print(self.hashes)



    def scan_domain_response(self):



        self.root4 = Tk()

        self.root4.title("Detailed info")
        self.root4.geometry("700x500")
        self.detailed_hashes_text = Text(self.root4, heigh=30, width=80)
        self.detailed_hashes_text.pack()

        self.detailed_hashes_text.delete(1.0, END)


        self.domain = self.domain_text.get('1.0', 'end-1c')
        # print(self.domain)

        params = {'domain': self.domain, 'apikey': self.API_KEY}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,Gertautas"

        }

        self.response_domain = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params,
                                            headers=headers)
        self.response_domain_json = self.response_domain.json()
        self.response_domain_detected_urls = self.response_domain_json['detected_urls']

        #print(self.response_domain_json)

        self.detailed_hashes_text.insert(END, self.response_domain_detected_urls)

        pprint.pprint(self.response_domain_json)




    def write_to_csv(self):

        if os.path.exists(self.excel):
            os.remove(self.excel)

        with open(self.fname) as csvinput:
            with open(self.excel, 'w') as csvoutput:
                writer = csv.writer(csvoutput, lineterminator='\n')
                reader1 = csv.reader(csvinput)

                all = []
                row = next(reader1)
                row.append('Virustotal')
                all.append(row)

                #for row in reader1:
                 #   row.append(row[0])
                    #all.append(row)

                writer.writerows(all)

                j=0
                for i in self.hashes:
                    for line in open(self.fname, 'r+'):
                        csv_row=line.split()
                        if any(i in s for s in csv_row):
                            all2 = []
                            csv_row.append(self.csv_info[j])
                        # print(csv_row)
                            all2.append(csv_row)
                            #print(all2)
                            writer.writerows(all2)
                            j += 1


    def scan_hashes(self):

        self.root3.geometry("700x750")

        self.detailed_hashes_scan_text = Text(self.root3, heigh = 30, width = 80)
        self.detailed_hashes_scan_text.pack()

        self.write_to_scv = Button(self.root3, text = "Write to csv", width = 12, command = lambda : Application.write_to_csv(self))
        self.write_to_scv.pack()

        time.sleep(1)

        for f in self.hashes:
            #print(f)

            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': self.API_KEY, 'resource': f}
            self.response_hash = requests.get(url, params = params)
            self.data = self.response_hash.json()
            self.positives = self.data['positives']
            self.total = self.data['total']
            self.mcafee = self.data['scans']['McAfee']


            self.detailed_hashes_scan_text.insert(END, 'Hash ' + f + ' info: ' + '\n')
            #print(self.positives)
            self.detailed_hashes_scan_text.insert(END, 'Positive scans: ' + str(self.positives) + '\n')
            self.detailed_hashes_scan_text.insert(END,  'Total scan: ' + str(self.total) + '\n')
            #print(self.mcafee)
            self.detailed_hashes_scan_text.insert(END,'McAfee report: ' + str(self.mcafee))
            self.detailed_hashes_scan_text.insert(END, '\n' + '\n')
            #time.sleep(1)
            self.csv_info.append(str(f) + str(self.positives) + str(self.total) + str(self.mcafee))


    def open_csv_file(self):



        self.check = Checkbutton()
        self.f = open('file.txt', 'w')
        self.ff = pathlib.Path('file.txt')
        self.f_a = str(self.ff.absolute())
        self.f_ab = self.f_a.replace('\\', '/')


        #self.text.delete(1.0, END)
        self.fname = askopenfilename(filetypes=(("Excel log files", "*.csv"),
                                                ("Json files", "*.JSON;*.htm"),
                                                ("All files", "*.*")))

        self.text.insert(END, "File selected. Scanning file..." + '\n')

        if self.fname:
            try:

                i = 0
                print(self.dynamic_check)
                while i < len(self.dynamic_check):
                    self.dynamic_check[i].destroy()
                    #print(self.dynamic_check[i])
                    i += 1

                self.count = 4

                Label(self,text =self.fname).grid(row=2, column=2)


                columns = defaultdict(list)
                with open(self.fname) as ff:
                    reader = csv.DictReader(ff)
                    for row in reader:
                        for (k, v) in row.items():
                            columns[k].append(v)

                with open(self.fname) as f:
                    reader = csv.reader(f)
                    self.stulpeliai = next(reader)
                    #print(self.stulpeliai)

                    for f in self.stulpeliai:
                        self.count +=1
                        self.stulpeliu_info = columns[f]
                        #print(self.stulpeliu_info)
                        self.stulpeliu_info_json = json.dumps(self.stulpeliu_info)

                        if self.virushare in self.stulpeliu_info_json:
                            self.check = Checkbutton(text=f, variable=self.b)
                            self.check.grid(row=self.count, column=0, sticky=W)
                            self.dynamic_check.append(self.check)
                            #self.check.select()
                            #Label(self, text = f).grid(row = self.count, column = 0, sticky = W)
                            messagebox.showinfo("Information", "Hash found in column: " + f)
                            self.hashes = re.findall(r"([a-fA-F\d]{32})", self.stulpeliu_info_json)
                            with open(self.f_ab,'w') as outfile:
                                json.dump(self.hashes, outfile)
                        #time.sleep(1)

                    messagebox.showinfo("Informaction", "File is scanned! " )
                    self.text.insert(END, "File scanning done. " + '\n')
                    self.text.insert(END, '\n')

                    self.get_hashes = Button(self, text = "Get hashes", width = 12, command = lambda : Application.write_hashes_to_txt(self))
                    self.get_hashes.grid(row = self.count, column = 2)


                    #print(self.f_ab)




            except OSError as err:  # <- naked except is a bad idea
                showerror("Open Source File", "Failed to read file\n'%s'" % self.fname)
                print("klaida cia ---> ".format(err))



root = Tk()
root.title("Bakalauras")
root.geometry("870x700")
app = Application(root)

app.mainloop()
