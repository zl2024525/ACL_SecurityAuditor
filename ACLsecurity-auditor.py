import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog

import os
import re

import sqlite3
import time

# List of dangerous ports and services
dangerous_ports = ['135', '139', '445', '21', '23', '67', '68', '69', '3389', '1433', '1521', '3306', 'telnet', 'ftp', 'mysql', 'oracle', 'sqlserver']
# Initial path, set to empty string
input_path = r''
# Output path, set to empty string
output_path = r''
# Separator line
separator = '------------------------------------------------'

# Global list to store information
info_list = []

# Global variable to store detection results
global detection_info_list
detection_info_list = []


def preprocess(file):
    global acl_list
    global device_type
    txt = open(file).read()
    if 'ip access-list' in txt:
        first_index = txt.find('ip access')
        second_index = txt.rfind('ip access')
        third_index = txt[second_index:].find('!') + second_index
        acl_list = txt[first_index:third_index].split('!')
        device_type = 'cisco'
    else:
        first_index = txt.find('acl')
        second_index = txt.rfind('acl')
        third_index = txt[second_index:].find('#') + second_index
        acl_list = txt[first_index:third_index].split('#')
        device_type = 'huawei'


# Variable to store the result text
result_text_widget = None


def ruleA1(i):
    global match_count
    global strict_rule_count
    global broad_rule_count
    try:
        if re.findall(r'\bany\b', i):
            any_count = len(re.findall(r'\bany\b', i))
            if any_count == 3:
                info = 'Allow traffic from any source, to any destination, using any protocol (Prohibited rule): ' + i
                temp_data.append(info)
                log.write(info + '\n')
                info_list.append(info)
                match_count += 1
                strict_rule_count += 1
    except:
        pass
    try:
        if re.findall(r'\bany\b', i):
            any_count = len(re.findall(r'\bany\b', i))
            if any_count == 4:
                info = 'Allow traffic from any source, to any destination, using any protocol, on any port (Prohibited rule): ' + i
                temp_data.append(info)
                log.write(info + '\n')
                info_list.append(info)
                match_count += 1
                strict_rule_count += 1
    except:
        pass
    try:
        if re.search(r'udp', i) and re.search(r'permit', i):
            info = 'Allow User Datagram Protocol (UDP) traffic (Prohibited rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            strict_rule_count += 1
    except:
        pass
    try:
        if re.search(r'eq\s\d+', i) and re.search(r'permit', i):
            if re.search(r'eq\s\d+', i).group().lstrip('eq ') in dangerous_ports:
                info = 'Allow traffic on dangerous or potentially risky ports (Prohibited rule): ' + i
                temp_data.append(info)
                log.write(info + '\n')
                info_list.append(info)
                match_count += 1
                strict_rule_count += 1
    except:
        pass
    try:
        if re.search(r'permit', i) and re.search(r'any', i):
            info = 'Allow traffic from any source (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if re.findall(r'\bany\b', i):
            any_count = len(re.findall(r'\bany\b', i))
            if any_count == 2:
                info = 'Allow traffic from any source to any destination (Broad rule): ' + i
                temp_data.append(info)
                log.write(info + '\n')
                info_list.append(info)
                match_count += 1
                broad_rule_count += 1
    except:
        pass
    try:
        if re.search(r'source\s(\d+\.){3}0|source\s\(\d+\.{2}0.0', i) and re.search(r'permit', i):
            info = 'Allow traffic from a wide range of source IP addresses (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if re.search(r'destination\s(\d+\.){3}0|destination\s\(\d+\.{2}0.0', i) and re.search(r'permit', i):
            info = 'Allow traffic to a wide range of destination IP addresses (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if re.search(r'permit', i) and re.search(r'destination', i) and not re.search(r'source', i):
            info = 'No specific source IP address specified (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if re.search(r'permit', i) and re.search(r'source', i) and not re.search(r'destination', i):
            info = 'No specific destination IP address specified (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if not re.search(r'eq', i) and not re.search(r'range', i) and re.search(r'permit', i) and not re.search(r'any', i):
            info = 'No specific port specified (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass


def ruleA2(i, o):
    global match_count
    global conflict_rule_count
    global coverage_rule_count
    global redundancy_rule_count
    if re.search(r'rule\s\d+', i).group() != re.search(r'rule\s\d+', o).group():
        if re.search(r'permit|deny', i).group() != re.search(r'permit|deny', o).group():
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and re.search(r'source\s\s(\d+\.){3}\d+', i).group() == re.search(r'source\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'destination\s\s(\d+\.){3}\d+', i).group() == re.search(r'destination\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Both allow and deny rules exist for the same address and port (Conflict rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    conflict_rule_count += 1
            except:
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and re.search(r'source\s(\d+\.){3}\d+', i).group() == re.search(r'source\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'destination\s(\d+\.){3}\d+', i).group() == re.search(r'destination\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() != re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Port conflict (Conflict rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    conflict_rule_count += 1
            except:
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and re.search(r'source\s(\d+\.){3}', i).group() == re.search(r'source\s(\d+\.){3}', o).group() \
                        and re.search(r'source\s(\d+\.){3}0', i) \
                        and re.search(r'destination\s(\d+\.){3}\d+', i).group() == re.search(r'destination\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Source IP address conflict (Conflict rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    conflict_rule_count += 1
            except:
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and re.search(r'destination\s(\d+\.){3}', i).group() == re.search(r'destination\s(\d+\.){3}', o).group() \
                        and re.search(r'destination\s(\d+\.){3}0', i) \
                        and re.search(r'source\s(\d+\.){3}\d+', i).group() == re.search(r'source\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Destination IP address conflict (Conflict rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    conflict_rule_count += 1
            except:
                pass
        elif re.search(r'permit|deny', i).group() == re.search(r'permit|deny', o).group():
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and re.search(r'source\s(\d+\.){3}', i).group() == re.search(r'source\s(\d+\.){3}', o).group() \
                        and re.search(r'destination\s(\d+\.){3}\d+', i).group() == re.search(r'destination\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'source\s(\d+\.){3}0|source\s(\d+\.){2,}0.0', i) \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Source IP address coverage (Coverage rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    coverage_rule_count += 1
            except:
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and re.search(r'source\s(\d+\.){3}\d+', i).group() == re.search(r'source\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'destination\s(\d+\.){3}', i).group() == re.search(r'destination\s(\d+\.){3}', o).group() \
                        and re.search(r'destination\s(\d+\.){3}0|destination\s(\d+\.){2,}0.0', i) \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Destination IP address coverage (Coverage rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    coverage_rule_count += 1
            except:
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and re.search(r'source\s(\d+\.){3}\d+', i).group() == re.search(r'source\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'destination\s(\d+\.){3}\d+', i).group() == re.search(r'destination\s(\d+\.){3}\d+', o).group() \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Duplicate action, port, source IP, and destination IP address (Redundancy rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    redundancy_rule_count += 1
            except:
                pass


def ruleB1(i):
    global match_count
    global strict_rule_count
    global broad_rule_count
    try:
        if re.search(r'permit', i) and re.search(r'any\s[host]*\s*\d*.*any', i) and not re.search(r'destination', i):
            info = 'Allow traffic using any protocol (Prohibited rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            strict_rule_count += 1
    except:
        pass
    try:
        if re.search(r'permit', i) and re.search(r'any\s[host]*\s*\d*.*any', i) and not re.search(r'eq \d+', i):
            info = 'Allow traffic on any port (Prohibited rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            strict_rule_count += 1
    except:
        pass
    try:
        if re.search(r'udp', i) and re.search(r'permit', i):
            info = 'Allow User Datagram Protocol (UDP) traffic (Prohibited rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            strict_rule_count += 1
    except:
        pass
    try:
        if re.search(r'eq\s\d+', i) and re.search(r'permit', i):
            if re.search(r'eq\s\d+', i).group().lstrip('eq ') in dangerous_ports:
                info = 'Allow traffic on dangerous or potentially risky ports (Prohibited rule): ' + i
                temp_data.append(info)
                log.write(info + '\n')
                info_list.append(info)
                match_count += 1
                strict_rule_count += 1
    except:
        pass
    try:
        if re.search(r'permit', i) and re.search(r'any\s[host]*\s*\d*.*', i):
            info = 'Allow traffic from any source (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if re.search(r'permit', i) and re.search(r'\s\d+\.\d+\.\d+\.\d+\sany$', i) \
                and not re.search(r'destination', i):
            info = 'Allow access to any destination IP address (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if re.search(r'((?<=tcp\s)|(?<=ip\s)|(?<=udp\s)|(?<=icmp\s))[host\s]*(\d+\.){3}0|((?<=tcp\s)|(?<=ip\s)|(?<=udp\s)|(?<=icmp\s))[host\s]*(\d+\.){2}0.0', i) \
                and re.search(r'permit', i):
            info = 'Allow traffic from a wide range of source IP addresses (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if re.search(r'\s(\d+\.){3}0\s\S+\seq|\s(\d+\.){2}0.0\s\S+\seq|\s(\d+\.){3}0\s\S+255$|\s(\d+\.){2}0+.0\s\S+255$', i) \
                and re.search(r'permit', i):
            info = 'Allow traffic to a wide range of destination IP addresses (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass
    try:
        if not re.search(r'eq', i) and not re.search(r'range', i) and re.search(r'permit', i) and not re.search(r'any', i):
            info = 'No specific port specified (Broad rule): ' + i
            temp_data.append(info)
            log.write(info + '\n')
            info_list.append(info)
            match_count += 1
            broad_rule_count += 1
    except:
        pass


def ruleB2(i, o):
    global match_count
    global conflict_rule_count
    global coverage_rule_count
    if acl.index(i) != acl.index(o):
        if re.search(r'permit|deny', i).group() != re.search(r'permit|deny', o).group():
            try:
                if re.search(r'tcp|ip|udp|icmp', i).group() == re.search(r'tcp|ip|udp|icmp', o).group() \
                        and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][0] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', o) if '0.255' not in x][0] \
                        and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][1] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', o) if '0.255' not in x][1] \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Both allow and deny rules exist for the same address and port (Conflict rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    conflict_rule_count += 1
            except:
                pass
            try:
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', i) if '0.0.0' not in x][0] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', o) if '0.0.0' not in x][0] \
                        and re.search(r'((?<=tcp\s)|(?<=ip\s)|(?<=udp\s)|(?<=icmp\s))[host\s]*(\d+\.){3}0', i) \
                        and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][1] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', o) if '0.255' not in x][1] \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Source IP address conflict (Conflict rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    conflict_rule_count += 1
            except:
                pass
            try:
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][0] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', o) if '0.255' not in x][0] \
                        and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', i) if '0.0.0' not in x][1] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', o) if '0.0.0' not in x][1] \
                        and re.search(r'(\d+\.){3}0', [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][1]).group() \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Destination IP address conflict (Conflict rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    conflict_rule_count += 1
            except:
                pass
        elif re.search(r'permit|deny', i).group() == re.search(r'permit|deny', o).group():
            try:
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', i) if '0.0.0' not in x][0] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', o) if '0.0.0' not in x][0] \
                        and re.search(r'(tcp|udp|icmp)+\s[host\s]*(\d+\.){3}0', i) \
                        and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][1] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', o) if '0.255' not in x][1] \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Source IP address coverage (Coverage rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    coverage_rule_count += 1
            except:
                pass
            try:
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][0] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', o) if '0.255' not in x][0] \
                        and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', i) if '0.0.0' not in x][1] \
                        == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.', o) if '0.0.0' not in x][1] \
                        and re.search(r'(\d+\.){3}0', [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+', i) if '0.255' not in x][1]).group() \
                        and re.search(r'eq\s\d+|range\s[\d+\s]*', i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*', o).group():
                    info = 'Destination IP address coverage (Coverage rule): ' + i + '<||>' + o
                    temp_data.append(info)
                    log.write(info + '\n')
                    info_list.append(info)
                    match_count += 1
                    coverage_rule_count += 1
            except:
                pass


# Virtual ACL detection function
def perform_detection(filepath):
    # Implement ACL detection function
    # Return a string representing the detection result
    input_path = filepath
    global output_path, acl_count, total_match_count, total_strict_rule_count, total_broad_rule_count, total_conflict_rule_count, total_coverage_rule_count, total_redundancy_rule_count
    result = "Detection results are as follows:"
    result += '\n' + separator + '\n'
    global acl_name
    global log
    global acl
    # Get the file list and iterate
    file_list = os.listdir(input_path)
    for file in file_list:
        n = 0
        log = open(output_path + file + '.txt', 'a')
        file_name = file
        info = separator + '\nAudit of configuration file [' + file + '] started'
        log.write(info + '\n')
        info_list.append(info)
        preprocess(os.path.join(input_path, file))
        # Count the number of ACLs
        if device_type == 'huawei':
            acl_count = str(acl_list).count('acl')
        elif device_type == 'cisco':
            acl_count = str(acl_list).count('ip access')
        total_match_count = 0
        total_strict_rule_count = 0
        total_broad_rule_count = 0
        total_conflict_rule_count = 0
        total_coverage_rule_count = 0
        total_redundancy_rule_count = 0
        while n < len(acl_list):
            acl = acl_list[n].split('\n')
            acl = [x.strip() for x in acl if x.strip() != '']
            try:
                global match_count
                global strict_rule_count
                global broad_rule_count
                global conflict_rule_count
                global coverage_rule_count
                global redundancy_rule_count
                match_count = 0
                strict_rule_count = 0
                broad_rule_count = 0
                conflict_rule_count = 0
                coverage_rule_count = 0
                redundancy_rule_count = 0
                acl_name = re.search(r'\w+$|\d+$', acl[0])
                if acl_name is None:
                    total_match_count += match_count
                    total_strict_rule_count += strict_rule_count
                    total_broad_rule_count += broad_rule_count
                    total_conflict_rule_count += conflict_rule_count
                    total_coverage_rule_count += coverage_rule_count
                    total_redundancy_rule_count += redundancy_rule_count
                    n += 1
                    continue
                acl_name = acl_name.group()
                info = separator + '\n[ACL]: ' + acl_name + '\n[Number of rules]: ' + str(len(acl) - 1)
                temp_data.append(info + '\n--------------------')
                log.write(info + '\n')
                info_list.append(info)
                # Check if there is a default deny rule
                deny = 'false'
                if re.search(r'deny\sany\'\]$', str(acl)):
                    deny = 'true'
                else:
                    pass
                # Call different rule detection functions based on the device type
                if device_type == 'huawei':
                    for i in acl:
                        if re.search(r'rule', i):
                            ruleA1(i)
                            for o in acl:
                                if re.search(r'rule', o):
                                    ruleA2(i, o)
                elif device_type == 'cisco':
                    for i in acl:
                        if 'ip access-list' not in i:
                            ruleB1(i)
                            for o in acl:
                                if 'ip access-list' not in o:
                                    ruleB2(i, o)
                # Output the detection results
                if deny == 'false':
                    info = '[No default deny rule found]'
                    log.write(info + '\n')
                    info_list.append(info)
                    temp_data.append(info)
                info = '--------------------\n[' + acl_name + '] Total security risks found: ' + str(match_count) + ' items\n' + \
                       'Among them:\n' + 'Prohibited rules: ' + str(strict_rule_count) + ' items\n' + 'Broad rules: ' + str(broad_rule_count) + ' items\n' + \
                       'Conflict rules: ' + str(conflict_rule_count) + ' items\n' + 'Coverage rules: ' + str(coverage_rule_count) + ' items\n' + 'Redundancy rules: ' + str(redundancy_rule_count) + ' items\n' + separator
                temp_data.append(info)
                log.write(info + '\n')
                info_list.append(info)
            except IndexError:
                pass
            # Update the ACL and security vulnerability counts
            total_match_count += match_count
            total_strict_rule_count += strict_rule_count
            total_broad_rule_count += broad_rule_count
            total_conflict_rule_count += conflict_rule_count
            total_coverage_rule_count += coverage_rule_count
            total_redundancy_rule_count += redundancy_rule_count
            n += 1
        # Update the result variable with the ACL and security vulnerability counts
        temp_data.append(f'\n{acl_count}\n{total_match_count}')
        result += f'\nTotal number of valid ACLs: [{acl_count}]\nTotal number of security risks: [{total_match_count}]\nAmong them:\nTotal number of prohibited rules: [{total_strict_rule_count}]\n' \
                  f'Total number of broad rules: [{total_broad_rule_count}]\nTotal number of conflict rules: [{total_conflict_rule_count}]\nTotal number of coverage rules: [{total_coverage_rule_count}]\n' \
                  f'Total number of redundancy rules: [{total_redundancy_rule_count}]\n'
    # Update the result variable with the completion message
    result += f'\n{separator}\n====================Finished===================='
    # Return the result variable
    return result, acl_count, total_match_count, total_strict_rule_count, total_broad_rule_count, total_conflict_rule_count, total_coverage_rule_count, total_redundancy_rule_count


# Function to upload a file
def upload_file():
    filepath = filedialog.askdirectory().replace("/", '\\')
    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, filepath)


# Connect to the database and create a table if it doesn't exist
conn = sqlite3.connect('detection_results.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS detection_results (
                       file_path TEXT,
                       start_time TEXT,
                       end_time TEXT,
                       result_text TEXT
                   )''')
conn.commit()
conn.close()

temp_data = []


# Function to detect a file
def detect_file():
    global  temp_data
    temp_data = []
    filepath = file_path_entry.get()
    if filepath:
        result, acl_count, global_count, alljz_count, allkf_count, allpz_count, allfg_count, allry_count = perform_detection(filepath)
        result_text.delete("1.0", tk.END) 
        for info in info_list:
            result_text.insert(tk.END, info + '\n')  
        mat_(acl_count, global_count)
        info_list.clear()
        conn = sqlite3.connect('detection_results.db')
        cursor = conn.cursor()
        start_time = time.strftime('%Y-%m-%d %H:%M:%S')
        end_time = time.strftime('%Y-%m-%d %H:%M:%S')
        temp_1 = temp_data.pop().split()
        se = temp_1[0]
        acl = temp_1[1]
        cursor.execute(
            "INSERT INTO detection_results (file_path, start_time, end_time, result_text,acl,se) VALUES (?, ?, ?, ?,?,?)",
            (filepath, start_time, end_time, '\n'.join(temp_data),acl,se))
        conn.commit()
        conn.close()
    else:
        messagebox.showwarning("Warning", "Please select the file to be detected first!")


# Data processing and statistics module
def mat_(a_c, g_c):
    import matplotlib.pyplot as plt
    plt.rcParams['font.sans-serif'] = ['Microsoft YaHei']
    plt.rcParams['axes.unicode_minus'] = False
    colors = ['#9999ff', '#ff9999']  # Custom colors
    # Standardize the horizontal and vertical axes to ensure the pie chart is a perfect circle, otherwise it will be an ellipse
    plt.axes(aspect='equal')
    # Draw a pie chart
    try:
        _1 = round(a_c / (a_c + g_c), 1)
    except:
        _1 = 0
    try:
        _2 = round(g_c / (a_c + g_c), 1)
    except:
        _2 = 0
    plt.pie(x=[_1, _2],  # Plotting data
            labels=['Regular ACL Ratio', 'Security Vulnerability Ratio'],  # Add education level labels
            colors=colors,  # Set custom fill colors for the pie chart
            autopct='%.1f%%',  # Set the format of the percentage, here keeping one decimal place
            pctdistance=0.8,  # Set the distance between the percentage label and the center of the circle
            startangle=180,  # Set the initial angle of the pie chart
            radius=0.5,  # Set the radius of the pie chart
            counterclock=False,  # Whether it is counterclockwise, here set to clockwise
            wedgeprops={'linewidth': 0.2, 'edgecolor': 'red'},  # Set the properties of the inner and outer boundaries of the pie chart
            textprops={'fontsize': 10, 'color': 'black'},  # Set the properties of the text labels
            )
    plt.title('Pie Chart')  # Add a chart title
    plt.show()  # Display the graph


# Function to export results
def export_results():
    import tkinter.filedialog as filedialog
    import tkinter.messagebox as messagebox
    filepath = filedialog.asksaveasfilename(defaultextension=".txt")
    result = result_text.get("1.0", tk.END)
    with open(filepath, "w") as file:
        file.write(result)
    messagebox.showinfo("Export Successful", "The detection results have been successfully exported as a file.")


# Function to export details
def export_details(result_text_box):
    import tkinter.filedialog as filedialog
    import tkinter.messagebox as messagebox
    filepath = filedialog.asksaveasfilename(defaultextension=".txt")
    result = result_text_box.get("1.0", tk.END)
    with open(filepath, "w") as file:
        file.write(result)
    messagebox.showinfo("Export Successful", "The detailed information has been successfully exported as a file.")


# Delete selected row in the history interface
def delete_selected_row(history_table):
    selected_item = history_table.selection()
    if selected_item:
        # Get the data of the selected row
        values = history_table.item(selected_item, 'values')
        file_path = values[0]
        import sqlite3
        conn = sqlite3.connect('detection_results.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM detection_results WHERE file_path=?", (file_path,))
        conn.commit()
        # Delete the selected row from the table
        history_table.delete(selected_item)


# Event after clicking the "View Details" button in the history interface
def view_details(history_table):
    selected_item = history_table.selection()
    if selected_item:
        # Get the data of the selected row
        values = history_table.item(selected_item, 'values')
        file_path = values[0]
        start_time = values[1]
        end_time = values[2]
        # Create a new window to display detailed information
        import tkinter as tk
        details_window = tk.Toplevel(window)
        details_window.title("Detailed Information")
        # Add labels in the new window to display detailed information
        file_path_label = tk.Label(details_window, text="File Path: " + file_path)
        file_path_label.pack()
        start_time_label = tk.Label(details_window, text="Start Time: " + start_time)
        start_time_label.pack()
        end_time_label = tk.Label(details_window, text="End Time: " + end_time)
        end_time_label.pack()
        result_text_label = tk.Label(details_window, text="Detection Result:")
        result_text_label.pack()
        # Create a text box to display the detection result
        result_text_box = tk.Text(details_window, width=130, height=45)
        result_text_box.pack()
        # Call the detection function to perform detection and insert the result into the text box
        # result_text, _, _, _, _, _, _, _ = perform_detection(file_path)
        global ALL_rows
        result_text_box.insert(tk.END, ALL_rows[int(selected_item[0].replace("I", '')) - 1][3])
        # Add an export button
        export_details_button = tk.Button(details_window, text="Export Details",
                                          command=lambda: export_details(result_text_box))
        export_details_button.pack()
    else:
        import tkinter.messagebox as messagebox
        messagebox.showwarning("Warning", "Please select a historical record to view details first!")


ALL_rows = None
# History records
def show_history():
    global ALL_rows
    import sqlite3
    conn = sqlite3.connect('detection_results.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM detection_results")
    conn.commit()
    rows = cursor.fetchall()
    ALL_rows = rows
    import tkinter as tk
    import tkinter.ttk as ttk
    history_window = tk.Toplevel(window)
    history_window.title("Historical Records")
    history_table = ttk.Treeview(history_window, columns=(
        "File Path", "Start Time", "End Time", "Correct ACL Count", "Security Vulnerability Count"), show="headings")
    history_table.heading("File Path", text="File Path")
    history_table.heading("Start Time", text="Start Time")
    history_table.heading("End Time", text="End Time")
    history_table.heading("Correct ACL Count", text="Correct ACL Count")
    history_table.heading("Security Vulnerability Count", text="Security Vulnerability Count")
    history_table.pack()

    for row in rows:
        row = list(row)
        del row[3]
        row[-1], row[-2] = row[-2], row[-1]
        history_table.insert("", "end", values=row)

    # Create a Frame to contain two buttons
    buttons_frame = tk.Frame(history_window)
    buttons_frame.pack()

    # Create a "View Details" button and place it in the Frame
    view_details_button = tk.Button(buttons_frame, text="Details", command=lambda: view_details(history_table))
    view_details_button.pack(side=tk.LEFT, padx=6)

    # Create a "Delete" button and place it in the Frame
    delete_button = tk.Button(buttons_frame, text="Delete", command=lambda: delete_selected_row(history_table))
    delete_button.pack(side=tk.LEFT, padx=6)

    conn.close()


# Create the main window
import tkinter as tk
window = tk.Tk()
window.title("Design and Implementation of ACL Security Audit Tool")

# Create GUI elements
file_path_label = tk.Label(window, text="Upload File Path:")
file_path_label.grid(row=0, column=0, padx=20, pady=20, sticky="W")

file_path_entry = tk.Entry(window, width=70)
file_path_entry.grid(row=0, column=1, padx=20, pady=20)

# Assume the upload_file function is defined elsewhere
upload_button = tk.Button(window, text="Upload", command=upload_file)
upload_button.grid(row=0, column=2, padx=20, pady=20)

# Assume the detect_file function is defined elsewhere
detect_button = tk.Button(window, text="Detect", command=detect_file)
detect_button.grid(row=0, column=3, padx=20, pady=20)

result_text = tk.Text(window, width=130, height=45)
result_text.grid(row=1, column=0, columnspan=4, padx=20, pady=20)

export_button = tk.Button(window, text="Export Results", command=export_results)
export_button.grid(row=2, column=0, padx=20, pady=20)

history_button = tk.Button(window, text="Historical Records", command=show_history)
history_button.grid(row=2, column=3, padx=20, pady=20)

# Run the main loop
window.mainloop()