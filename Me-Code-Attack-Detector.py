# -*- coding: utf-8 -*-
"""
Created on Tue Feb  27 08:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Me Code Attack Detector")
print(Fore.GREEN+font)


import psutil
import os
import re
import sys
import time
from datetime import datetime
import mmap

# Suspicious patterns we can look for in the memory or executable
SUSPICIOUS_PATTERNS = [
    r"exec\(",  # Detect execution of code (e.g., 'exec' in Python)
    r"system\(",  # Common for system command injection
    r"CreateRemoteThread",  # A known API for code injection
    r"VirtualAlloc",  # Known for memory allocation, used in injection
    r"shellcode",  # Detect shellcode pattern (custom for demonstration)
]

# Function to search for suspicious patterns in the memory of a process
def check_process_for_malicious_patterns(pid):
    try:
        # Get process by PID
        process = psutil.Process(pid)

        # Fetch the process name and command line arguments
        process_name = process.name()
        cmdline = process.cmdline()

        # Check if any suspicious pattern exists in the command line
        for pattern in SUSPICIOUS_PATTERNS:
            if any(re.search(pattern, arg) for arg in cmdline):
                print(f"Suspicious pattern found in command line of {process_name} (PID: {pid}): {pattern}")
                return True

        print(f"No suspicious patterns found in {process_name} (PID: {pid})")
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        print(f"Could not access process with PID {pid}. It may no longer exist or be inaccessible.")
        return False

# Function to analyze memory dump (dummy implementation for illustration)
def analyze_memory_dump(pid):
    try:
        process = psutil.Process(pid)
        mem_info = process.memory_maps()

        print(f"Analyzing memory dump for PID {pid}...")
        for region in mem_info:
            # Simulate memory dump analysis (this part would need real memory dump techniques)
            print(f"Region: {region.path} - {region.rss} bytes")
            if region.rss > 1024 * 1024:  # Example threshold, assume large memory usage is suspicious
                print(f"Suspicious memory usage detected in region: {region.path} ({region.rss} bytes)")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"Could not access memory of PID {pid}. It may no longer exist or be inaccessible.")

# Function to perform advanced pattern detection on process memory
def advanced_pattern_detection(pid):
    try:
        process = psutil.Process(pid)
        memory = process.memory_info().rss

        # For demonstration purposes, you can simulate memory dump and analyze content
        print(f"Performing advanced pattern detection on process {pid}")
        # For real-world use, memory analysis APIs or external tools like pydbg should be used
        # Example of detecting suspicious shellcode (dummy logic here)
        if "shellcode" in str(memory):  # Simulate detecting shellcode
            print(f"Suspicious shellcode detected in process {pid}")
            return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"Could not access memory of PID {pid}. It may no longer exist or be inaccessible.")
        return False

# Real-time monitoring of processes for suspicious code injection
def real_time_monitoring():
    print("Starting real-time monitoring of processes...")
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            pid = proc.info['pid']
            name = proc.info['name']
            cmdline = proc.info['cmdline']
            print(f"Monitoring process {name} (PID: {pid})")
            
            # Perform the pattern detection and memory analysis
            if check_process_for_malicious_patterns(pid):
                print(f"[ALERT] Malicious code detected in process {name} (PID: {pid})")
            
            analyze_memory_dump(pid)
            if advanced_pattern_detection(pid):
                print(f"[ALERT] Advanced pattern detected in process {name} (PID: {pid})")
        
        # Sleep for a specified period before re-checking processes (for real-time monitoring)
        time.sleep(10)  # Adjust as needed to make monitoring more/less frequent

# Function to list all running processes and allow user to select one for analysis
def list_processes_and_detect_malicious_code():
    print("Listing all running processes:")
    
    # Get all running processes
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        processes.append((proc.info['pid'], proc.info['name'], proc.info['cmdline']))

    # Display the list of processes
    for i, (pid, name, cmdline) in enumerate(processes):
        print(f"{i+1}. {name} (PID: {pid}) - {cmdline}")

    # Allow user to select a process
    try:
        process_index = int(input("\nEnter the number of the process you want to analyze (0 to exit): ")) - 1
        if process_index < 0 or process_index >= len(processes):
            print("Invalid choice. Exiting...")
            return

        selected_pid = processes[process_index][0]
        print(f"\nAnalyzing process with PID: {selected_pid}")
        if check_process_for_malicious_patterns(selected_pid):
            print(f"[ALERT] Malicious code detected in process with PID: {selected_pid}")
        else:
            print(f"[INFO] No malicious code detected in process with PID: {selected_pid}")
    
    except ValueError:
        print("Invalid input. Please enter a valid process number.")
        return

# Main function to prompt user and run the program
def main():
    print("Welcome to the Me Code Attack Detector\n")
    while True:
        print("\nPlease choose an option:")
        print("1. List running processes and check for suspicious code injection.")
        print("2. Start real-time monitoring for code injection.")
        print("3. Exit")

        choice = input("Enter your choice:").strip()
        if choice == '1':
            list_processes_and_detect_malicious_code()
        elif choice == '2':
            real_time_monitoring()
        elif choice == '3':
            print("Exiting program.")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
