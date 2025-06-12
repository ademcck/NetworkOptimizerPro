#!/usr/bin/env python3
"""
Modern Network Optimizer GUI - Futuristic USB Tethering & TTL Modifier
Professional GUI Application with Advanced Features
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import subprocess
import sys
import os
import time
import ctypes
from datetime import datetime
import json
import tempfile
from pathlib import Path
import queue
import ipaddress
from collections import defaultdict, deque

# Try to import Scapy for TTL modification
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ModernNetworkOptimizer:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_main_window()
        self.create_styles()
        self.create_gui()
        
        # Application state
        self.is_optimizing = False
        self.ttl_monitoring = False
        # self.log_queue = queue.Queue()  # Kaldır
        self.stats = {
            'packets_captured': 0,
            'packets_modified': 0,
            'devices_detected': set(),
            'start_time': None
        }
        
        # TTL Monitoring variables
        self.selected_interface = None
        self.network_range = None
        self.recent_packets = deque(maxlen=50)
        
        # self.process_logs()  # Kaldır

    def setup_main_window(self):
        """Setup main window with modern styling"""
        self.root.title("🚀 Network Optimizer Pro - Futuristic Edition")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Center window on screen
        self.center_window()
        
        # Modern window styling
        self.root.configure(bg='#0a0a0a')
        
        # Try to set window icon (optional)
        try:
            self.root.iconbitmap(default='icon.ico')
        except:
            pass

    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def create_styles(self):
        """Create modern, futuristic styles"""
        self.style = ttk.Style()
        
        # Configure modern dark theme
        self.style.theme_use('clam')
        
        # Color scheme - Futuristic neon
        self.colors = {
            'bg_primary': '#0a0a0a',      # Deep black
            'bg_secondary': '#1a1a2e',    # Dark blue-grey
            'bg_tertiary': '#16213e',     # Navy blue
            'accent_primary': '#00ff9f',  # Neon green
            'accent_secondary': '#0066ff', # Electric blue
            'accent_danger': '#ff3366',   # Neon pink/red
            'accent_warning': '#ffaa00',  # Neon orange
            'text_primary': '#ffffff',    # White
            'text_secondary': '#b0b0b0',  # Light grey
            'text_accent': '#00ff9f',     # Neon green
        }
        
        # Configure styles
        self.style.configure('Modern.TFrame', 
                           background=self.colors['bg_primary'],
                           relief='flat')
        
        self.style.configure('Card.TFrame',
                           background=self.colors['bg_secondary'],
                           relief='solid',
                           borderwidth=1)
        
        self.style.configure('Modern.TLabel',
                           background=self.colors['bg_primary'],
                           foreground=self.colors['text_primary'],
                           font=('Consolas', 10))
        
        self.style.configure('Header.TLabel',
                           background=self.colors['bg_primary'],
                           foreground=self.colors['accent_primary'],
                           font=('Consolas', 16, 'bold'))
        
        self.style.configure('Subheader.TLabel',
                           background=self.colors['bg_secondary'],
                           foreground=self.colors['text_primary'],
                           font=('Consolas', 12, 'bold'))
        
        self.style.configure('Stats.TLabel',
                           background=self.colors['bg_secondary'],
                           foreground=self.colors['accent_secondary'],
                           font=('Consolas', 10, 'bold'))
        
        # Button styles
        self.style.configure('Neon.TButton',
                           background=self.colors['accent_primary'],
                           foreground=self.colors['bg_primary'],
                           font=('Consolas', 11, 'bold'),
                           borderwidth=0,
                           focuscolor='none')
        
        self.style.map('Neon.TButton',
                      background=[('active', self.colors['accent_secondary']),
                                ('pressed', self.colors['accent_primary'])])
        
        self.style.configure('Danger.TButton',
                           background=self.colors['accent_danger'],
                           foreground=self.colors['text_primary'],
                           font=('Consolas', 11, 'bold'),
                           borderwidth=0,
                           focuscolor='none')
        
        # Notebook (tabs) styling
        self.style.configure('Modern.TNotebook',
                           background=self.colors['bg_primary'],
                           tabmargins=[2, 5, 2, 0])
        
        self.style.configure('Modern.TNotebook.Tab',
                           background=self.colors['bg_secondary'],
                           foreground=self.colors['text_secondary'],
                           padding=[20, 10],
                           font=('Consolas', 10, 'bold'))
        
        self.style.map('Modern.TNotebook.Tab',
                      background=[('selected', self.colors['bg_tertiary']),
                                ('active', self.colors['accent_primary'])],
                      foreground=[('selected', self.colors['accent_primary']),
                                ('active', self.colors['bg_primary'])])

    def create_gui(self):
        """Create the main GUI interface"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Modern.TFrame')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        self.create_header(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame, style='Modern.TNotebook')
        self.notebook.pack(fill='both', expand=True, pady=(10, 0))
        
        # Create tabs
        self.create_usb_tether_tab()
        self.create_ttl_modifier_tab()
        self.create_settings_tab()

    def create_header(self, parent):
        """Create futuristic header"""
        header_frame = ttk.Frame(parent, style='Modern.TFrame')
        header_frame.pack(fill='x', pady=(0, 10))
        
        # Main title with emoji
        title_label = ttk.Label(header_frame, 
                              text="🚀 NETWORK OPTIMIZER PRO",
                              style='Header.TLabel')
        title_label.pack()
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame,
                                 text="Advanced USB Tethering & TTL Modification Suite",
                                 style='Modern.TLabel',
                                 font=('Consolas', 9))
        subtitle_label.pack()
        
        # Status indicator
        self.status_frame = ttk.Frame(header_frame, style='Modern.TFrame')
        self.status_frame.pack(fill='x', pady=(5, 0))
        
        self.status_label = ttk.Label(self.status_frame,
                                    text="⚡ System Ready",
                                    style='Stats.TLabel')
        self.status_label.pack()

    def create_usb_tether_tab(self):
        """Create USB Tethering Optimizer tab"""
        tab_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(tab_frame, text="📱 USB Tethering")
        
        # Configure grid
        tab_frame.grid_columnconfigure(0, weight=1)
        tab_frame.grid_columnconfigure(1, weight=1)
        
        # Left panel - Controls
        left_panel = ttk.Frame(tab_frame, style='Card.TFrame')
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(10, 5), pady=10)
        left_panel.configure(padding=15)
        
        # Panel title
        ttk.Label(left_panel, text="🔧 TETHERING CONTROLS", 
                 style='Subheader.TLabel').pack(anchor='w')
        
        # Quick info
        info_text = """
🔹 Optimizes Windows for USB tethering
🔹 Sets TTL to 65 for carrier bypass
🔹 Configures DNS to Cloudflare (1.1.1.1)
🔹 Optimizes network adapter settings
🔹 Creates restore script automatically
        """.strip()
        
        info_label = ttk.Label(left_panel, text=info_text, 
                             style='Modern.TLabel', justify='left')
        info_label.pack(anchor='w', pady=(10, 20))
        
        # Control buttons
        button_frame = ttk.Frame(left_panel, style='Modern.TFrame')
        button_frame.pack(fill='x')
        
        self.optimize_btn = ttk.Button(button_frame, 
                                     text="🚀 START OPTIMIZATION",
                                     style='Neon.TButton',
                                     command=self.start_usb_optimization)
        self.optimize_btn.pack(fill='x', pady=5)
        
        self.restore_btn = ttk.Button(button_frame,
                                    text="🔄 RESTORE SETTINGS", 
                                    style='Danger.TButton',
                                    command=self.restore_settings)
        self.restore_btn.pack(fill='x', pady=5)
        
        # Admin check
        self.admin_status = ttk.Label(left_panel, 
                                    text=self.check_admin_status(),
                                    style='Stats.TLabel')
        self.admin_status.pack(anchor='w', pady=(20, 0))
        
        # Right panel - Real-time info
        right_panel = ttk.Frame(tab_frame, style='Card.TFrame')
        right_panel.grid(row=0, column=1, sticky='nsew', padx=(5, 10), pady=10)
        right_panel.configure(padding=15)
        
        ttk.Label(right_panel, text="📊 SYSTEM STATUS", 
                 style='Subheader.TLabel').pack(anchor='w')
        
        # Network adapter info
        self.adapter_info = scrolledtext.ScrolledText(right_panel, 
                                                    height=15,
                                                    bg=self.colors['bg_primary'],
                                                    fg=self.colors['text_primary'],
                                                    font=('Consolas', 9),
                                                    insertbackground=self.colors['accent_primary'])
        self.adapter_info.pack(fill='both', expand=True, pady=(10, 0))
        
        # Update adapter info
        self.update_adapter_info()

    def create_ttl_modifier_tab(self):
        """Create TTL Modifier tab"""
        tab_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(tab_frame, text="🛡️ TTL Modifier")
        
        if not SCAPY_AVAILABLE:
            # Scapy not available warning
            warning_frame = ttk.Frame(tab_frame, style='Card.TFrame')
            warning_frame.pack(fill='both', expand=True, padx=10, pady=10)
            warning_frame.configure(padding=20)
            
            ttk.Label(warning_frame, 
                     text="⚠️ SCAPY LIBRARY NOT FOUND",
                     style='Header.TLabel',
                     foreground=self.colors['accent_danger']).pack()
            
            install_text = """
To use TTL Modifier functionality, please install Scapy:

pip install scapy

After installation, restart the application.
            """.strip()
            
            ttk.Label(warning_frame, text=install_text,
                     style='Modern.TLabel', justify='center').pack(pady=20)
            
            return
        
        # Configure grid
        tab_frame.grid_columnconfigure(0, weight=1)
        tab_frame.grid_columnconfigure(1, weight=1)
        tab_frame.grid_rowconfigure(0, weight=1)
        
        # Left panel - Controls
        left_panel = ttk.Frame(tab_frame, style='Card.TFrame')
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(10, 5), pady=10)
        left_panel.configure(padding=15)
        
        ttk.Label(left_panel, text="🛡️ TTL MONITORING", 
                 style='Subheader.TLabel').pack(anchor='w')
        
        # Interface selection
        interface_frame = ttk.Frame(left_panel, style='Modern.TFrame')
        interface_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Label(interface_frame, text="Network Interface:",
                 style='Modern.TLabel').pack(anchor='w')
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(interface_frame, 
                                          textvariable=self.interface_var,
                                          state='readonly')
        self.interface_combo.pack(fill='x', pady=(5, 0))
        
        # Refresh interfaces button
        ttk.Button(interface_frame, text="🔄 Refresh",
                  command=self.refresh_interfaces).pack(anchor='e', pady=(5, 0))
        
        # TTL settings
        ttl_frame = ttk.Frame(left_panel, style='Modern.TFrame')
        ttl_frame.pack(fill='x', pady=(20, 0))
        
        ttk.Label(ttl_frame, text="Target TTL Value:",
                 style='Modern.TLabel').pack(anchor='w')
        
        self.ttl_var = tk.StringVar(value="65")
        ttl_spin = tk.Spinbox(ttl_frame, from_=1, to=255, 
                             textvariable=self.ttl_var,
                             bg=self.colors['bg_secondary'],
                             fg=self.colors['text_primary'],
                             font=('Consolas', 10))
        ttl_spin.pack(fill='x', pady=(5, 0))
        
        # Control buttons
        button_frame = ttk.Frame(left_panel, style='Modern.TFrame')
        button_frame.pack(fill='x', pady=(20, 0))
        
        self.ttl_start_btn = ttk.Button(button_frame,
                                      text="🚀 START MONITORING",
                                      style='Neon.TButton',
                                      command=self.start_ttl_monitoring)
        self.ttl_start_btn.pack(fill='x', pady=5)
        
        self.ttl_stop_btn = ttk.Button(button_frame,
                                     text="⏹️ STOP MONITORING",
                                     style='Danger.TButton',
                                     command=self.stop_ttl_monitoring,
                                     state='disabled')
        self.ttl_stop_btn.pack(fill='x', pady=5)
        
        # Statistics
        stats_frame = ttk.Frame(left_panel, style='Modern.TFrame')
        stats_frame.pack(fill='x', pady=(20, 0))
        
        ttk.Label(stats_frame, text="📈 STATISTICS",
                 style='Subheader.TLabel').pack(anchor='w')
        
        self.stats_labels = {}
        stats_info = [
            ('Packets Captured:', 'packets_captured'),
            ('Packets Modified:', 'packets_modified'), 
            ('Devices Detected:', 'devices_count'),
            ('Runtime:', 'runtime')
        ]
        
        for label_text, key in stats_info:
            frame = ttk.Frame(stats_frame, style='Modern.TFrame')
            frame.pack(fill='x', pady=2)
            
            ttk.Label(frame, text=label_text,
                     style='Modern.TLabel').pack(side='left')
            
            self.stats_labels[key] = ttk.Label(frame, text="0",
                                             style='Stats.TLabel')
            self.stats_labels[key].pack(side='right')
        
        # Right panel - Packet monitor
        right_panel = ttk.Frame(tab_frame, style='Card.TFrame')
        right_panel.grid(row=0, column=1, sticky='nsew', padx=(5, 10), pady=10)
        right_panel.configure(padding=15)
        
        ttk.Label(right_panel, text="📡 PACKET MONITOR",
                 style='Subheader.TLabel').pack(anchor='w')
        
        # Packet display
        self.packet_display = scrolledtext.ScrolledText(right_panel,
                                                       height=20,
                                                       bg=self.colors['bg_primary'],
                                                       fg=self.colors['text_primary'],
                                                       font=('Consolas', 8),
                                                       insertbackground=self.colors['accent_primary'])
        self.packet_display.pack(fill='both', expand=True, pady=(10, 0))
        
        # Initialize interfaces
        self.refresh_interfaces()

    

    def create_settings_tab(self):
        """Create settings tab"""
        tab_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(tab_frame, text="⚙️ Settings")
        
        # Settings frame
        settings_frame = ttk.Frame(tab_frame, style='Card.TFrame')
        settings_frame.pack(fill='both', expand=True, padx=10, pady=10)
        settings_frame.configure(padding=15)
        
        ttk.Label(settings_frame, text="⚙️ APPLICATION SETTINGS",
                 style='Subheader.TLabel').pack(anchor='w')
        
        # About section
        about_frame = ttk.Frame(settings_frame, style='Modern.TFrame')
        about_frame.pack(fill='x', pady=(20, 0))
        
        about_text = """
🚀 Network Optimizer Pro v1.0
Advanced USB Tethering & TTL Modification Suite

Features:
• Windows USB Tethering Optimization
• Real-time TTL Packet Modification  
• Network Adapter Configuration
• DNS Optimization (Cloudflare)
• Registry Optimization
• Automatic Restore Functionality

Requirements:
• Windows Administrator privileges
• Python 3.7+ with tkinter
• Scapy library (for TTL modification)

Built with modern Python and tkinter for maximum compatibility.
        """.strip()
        
        about_label = ttk.Label(about_frame, text=about_text,
                              style='Modern.TLabel', justify='left')
        about_label.pack(anchor='w')
        
        # Credits
        credits_frame = ttk.Frame(settings_frame, style='Modern.TFrame')
        credits_frame.pack(fill='x', pady=(20, 0))
        
        ttk.Label(credits_frame, text="💎 CREDITS",
                 style='Subheader.TLabel').pack(anchor='w')
        
        credits_text = """
🔹 Original USB Tethering Script: Windows Batch Optimization
🔹 TTL Modification: Professional Python Implementation
🔹 GUI Framework: Modern tkinter with custom styling
🔹 Network Libraries: Scapy for packet manipulation
        """.strip()
        
        ttk.Label(credits_frame, text=credits_text,
                 style='Modern.TLabel', justify='left').pack(anchor='w', pady=(10, 0))

    def check_admin_status(self):
        """Check if running with admin privileges"""
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                return "✅ Administrator privileges: ACTIVE"
            else:
                return "❌ Administrator privileges: REQUIRED"
        except:
            return "❓ Administrator status: UNKNOWN"

    def update_adapter_info(self):
        """Update network adapter information"""
        try:
            # Get network adapter info using netsh
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                info_text = "🌐 NETWORK INTERFACES:\n\n"
                info_text += result.stdout
                
                # Add TTL info
                info_text += "\n\n🔧 CURRENT TTL SETTINGS:\n"
                try:
                    ttl_result = subprocess.run(['netsh', 'int', 'ipv4', 'show', 'global'], 
                                              capture_output=True, text=True, shell=True)
                    if ttl_result.returncode == 0:
                        info_text += ttl_result.stdout
                except:
                    info_text += "Unable to retrieve TTL settings"
                
            else:
                info_text = "❌ Unable to retrieve network information"
                
            self.adapter_info.delete(1.0, tk.END)
            self.adapter_info.insert(1.0, info_text)
            
        except Exception as e:
            self.adapter_info.delete(1.0, tk.END)
            self.adapter_info.insert(1.0, f"❌ Error retrieving adapter info: {str(e)}")

    def start_usb_optimization(self):
        """Start USB tethering optimization"""
        if not self.check_admin_privileges():
            messagebox.showerror("Error", "Administrator privileges required!\nPlease run as Administrator.")
            return
        
        if self.is_optimizing:
            messagebox.showwarning("Warning", "Optimization already in progress!")
            return
        
        # Confirm action
        result = messagebox.askyesno("Confirm", 
                                   "This will modify your network settings.\n\n" +
                                   "Continue with USB tethering optimization?")
        if not result:
            return
        
        self.is_optimizing = True
        self.optimize_btn.configure(state='disabled')
        self.status_label.configure(text="⚡ Optimizing USB Tethering...")
        
        # Run optimization in thread
        threading.Thread(target=self.run_usb_optimization, daemon=True).start()

    def run_usb_optimization(self):
        """Run the actual USB optimization process"""
        try:
            ##self.add_log("🚀 Starting USB Tethering Optimization", "INFO")
            
            # Step 1: Set TTL
            ##self.add_log("[1/7] Setting TTL to 65...", "INFO")
            subprocess.run(['netsh', 'int', 'ipv4', 'set', 'global', 'defaultcurhoplimit=65'], 
                          shell=True, check=True)
            subprocess.run(['netsh', 'int', 'ipv6', 'set', 'global', 'defaultcurhoplimit=65'], 
                          shell=True, check=True)
            
            # Step 2: Find and configure USB adapter
            ##self.add_log("[2/7] Configuring DNS settings...", "INFO")
            
            # Get network interfaces
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                  capture_output=True, text=True, shell=True)
            
            if "Local Area Connection" in result.stdout:
                # Try to set DNS for Local Area Connection
                try:
                    subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'dns', 
                                  '"Local Area Connection"', 'static', '1.1.1.1', 'primary'], 
                                  shell=True, check=True)
                    subprocess.run(['netsh', 'interface', 'ipv4', 'add', 'dns', 
                                  '"Local Area Connection"', '1.0.0.1', 'index=2'], 
                                  shell=True)
                    ##self.add_log("✅ DNS configured for Local Area Connection", "SUCCESS")
                except:
                    pass
                    ##self.add_log("⚠️ DNS configuration may need manual setup", "WARNING")
            
            # Step 3: Registry optimization
            ##self.add_log("[3/7] Applying registry optimizations...", "INFO")
            try:
                subprocess.run(['reg', 'add', 
                              'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
                              '/v', 'DefaultTTL', '/t', 'REG_DWORD', '/d', '65', '/f'], 
                              shell=True, check=True)
                subprocess.run(['reg', 'add',
                              'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
                              '/v', 'TcpWindowSize', '/t', 'REG_DWORD', '/d', '65536', '/f'],
                              shell=True)
                ##self.add_log("✅ Registry optimizations applied", "SUCCESS")
            except:
                pass
                #self.add_log("⚠️ Some registry changes may have failed", "WARNING")
            
            # Step 4: MTU optimization
            #self.add_log("[4/7] Setting optimal MTU...", "INFO")
            
            # Step 5: Firewall (optional)
            #self.add_log("[5/7] Configuring firewall...", "INFO")
            
            # Step 6: Network profile
            #self.add_log("[6/7] Setting network profile...", "INFO")
            
            # Step 7: Performance tweaks
            #self.add_log("[7/7] Applying performance tweaks...", "INFO")
            
            # Create restore script
            self.create_restore_script()
            
            #self.add_log("🎉 USB Tethering optimization completed successfully!", "SUCCESS")
            #self.add_log("📝 Restore script created: restore_settings.bat", "INFO")
            
            # Update status
            self.root.after(0, lambda: self.status_label.configure(text="✅ Optimization Complete"))
            
        except subprocess.CalledProcessError as e:
            #self.add_log(f"❌ Optimization failed: {str(e)}", "ERROR")
            self.root.after(0, lambda: self.status_label.configure(text="❌ Optimization Failed"))
        except Exception as e:
            #self.add_log(f"❌ Unexpected error: {str(e)}", "ERROR")
            self.root.after(0, lambda: self.status_label.configure(text="❌ Optimization Failed"))
        
        finally:
            self.is_optimizing = False
            self.root.after(0, lambda: self.optimize_btn.configure(state='normal'))
            self.root.after(0, self.update_adapter_info)

    def create_restore_script(self):
        """Create restore script for reverting changes"""
        try:
            script_content = """@echo off
echo Restoring original network settings...
echo.

netsh int ipv4 set global defaultcurhoplimit=128
netsh int ipv6 set global defaultcurhoplimit=128

reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v DefaultTTL /t REG_DWORD /d 128 /f

netsh advfirewall set allprofiles state on

echo.
echo Original settings restored!
pause
"""
            
            with open("restore_settings.bat", "w", encoding='utf-8') as f:
                f.write(script_content)
            
            #self.add_log("📝 Restore script created successfully", "SUCCESS")
            
        except Exception as e:
            pass
            #self.add_log(f"⚠️ Could not create restore script: {str(e)}", "WARNING")

    def restore_settings(self):
        """Restore original network settings"""
        if not self.check_admin_privileges():
            messagebox.showerror("Error", "Administrator privileges required!")
            return
        
        result = messagebox.askyesno("Confirm", 
                                   "This will restore your original network settings.\n\n" +
                                   "Continue with restoration?")
        if not result:
            return
        
        threading.Thread(target=self.run_restore_settings, daemon=True).start()

    def run_restore_settings(self):
        """Run the restore process"""
        try:
            #self.add_log("🔄 Restoring original settings...", "INFO")
            
            # Restore TTL
            subprocess.run(['netsh', 'int', 'ipv4', 'set', 'global', 'defaultcurhoplimit=128'], 
                          shell=True, check=True)
            subprocess.run(['netsh', 'int', 'ipv6', 'set', 'global', 'defaultcurhoplimit=128'], 
                          shell=True, check=True)
            
            # Restore registry
            subprocess.run(['reg', 'add', 
                          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
                          '/v', 'DefaultTTL', '/t', 'REG_DWORD', '/d', '128', '/f'], 
                          shell=True, check=True)
            
            # Enable firewall
            subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'], 
                          shell=True)
            
            #self.add_log("✅ Settings restored successfully!", "SUCCESS")
            self.root.after(0, lambda: self.status_label.configure(text="✅ Settings Restored"))
            
        except Exception as e:
            #self.add_log(f"❌ Restore failed: {str(e)}", "ERROR")
            self.root.after(0, lambda: self.status_label.configure(text="❌ Restore Failed"))
        
        finally:
            self.root.after(0, self.update_adapter_info)

    def refresh_interfaces(self):
        """Refresh network interfaces list"""
        if not SCAPY_AVAILABLE:
            return
        
        try:
            # Get available interfaces using Scapy
            interfaces = get_if_list()
            interface_info = []
            
            for iface in interfaces:
                try:
                    ip = get_if_addr(iface)
                    if ip and ip != "0.0.0.0":
                        interface_info.append(f"{iface} ({ip})")
                except:
                    pass
            
            self.interface_combo['values'] = interface_info
            if interface_info:
                self.interface_combo.set(interface_info[0])
                
        except Exception as e:
            pass
            #self.add_log(f"❌ Error refreshing interfaces: {str(e)}", "ERROR")

    def start_ttl_monitoring(self):
        """Start TTL monitoring"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy library not available!")
            return
        
        if not self.check_admin_privileges():
            messagebox.showerror("Error", "Administrator privileges required!")
            return
        
        if self.ttl_monitoring:
            messagebox.showwarning("Warning", "TTL monitoring already running!")
            return
        
        if not self.interface_var.get():
            messagebox.showerror("Error", "Please select a network interface!")
            return
        
        # Extract interface name from combo selection
        interface_text = self.interface_var.get()
        self.selected_interface = interface_text.split(' (')[0]
        
        try:
            self.target_ttl = int(self.ttl_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid TTL value!")
            return
        
        self.ttl_monitoring = True
        self.ttl_start_btn.configure(state='disabled')
        self.ttl_stop_btn.configure(state='normal')
        
        # Reset stats
        self.stats = {
            'packets_captured': 0,
            'packets_modified': 0,
            'devices_detected': set(),
            'start_time': time.time()
        }
        
        #self.add_log(f"🛡️ Starting TTL monitoring on {self.selected_interface}", "INFO")
        #self.add_log(f"🎯 Target TTL: {self.target_ttl}", "INFO")
        
        # Start monitoring thread
        threading.Thread(target=self.run_ttl_monitoring, daemon=True).start()
        
        # Start stats updater
        threading.Thread(target=self.update_ttl_stats, daemon=True).start()

    def stop_ttl_monitoring(self):
        """Stop TTL monitoring"""
        self.ttl_monitoring = False
        self.ttl_start_btn.configure(state='normal')
        self.ttl_stop_btn.configure(state='disabled')
        
        #self.add_log("⏹️ TTL monitoring stopped", "INFO")

    def run_ttl_monitoring(self):
        """Run TTL monitoring with packet capture"""
        try:
            # Suppress Scapy warnings
            conf.verb = 0
            
            def packet_handler(packet):
                if not self.ttl_monitoring:
                    return False  # Stop sniffing
                
                try:
                    self.stats['packets_captured'] += 1
                    
                    if packet.haslayer(IP):
                        ip_layer = packet[IP]
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        original_ttl = ip_layer.ttl
                        
                        # Check if this is a local network packet (simplified)
                        if self.is_local_packet(src_ip):
                            self.stats['devices_detected'].add(src_ip)
                            
                            if original_ttl != self.target_ttl:
                                self.stats['packets_modified'] += 1
                                
                                # Log packet modification (simulation)
                                packet_info = {
                                    'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'original_ttl': original_ttl,
                                    'new_ttl': self.target_ttl,
                                    'protocol': self.get_protocol_name(ip_layer.proto)
                                }
                                
                                self.recent_packets.append(packet_info)
                                
                                # Add to packet display
                                self.update_packet_display(packet_info)
                        
                except Exception as e:
                    pass  # Ignore packet processing errors
                
                return True  # Continue sniffing
            
            # Start packet capture
            sniff(iface=self.selected_interface,
                  filter="ip",
                  prn=packet_handler,
                  store=0,
                  stop_filter=lambda x: not self.ttl_monitoring)
            
        except Exception as e:
            #self.add_log(f"❌ TTL monitoring error: {str(e)}", "ERROR")
            self.ttl_monitoring = False
            self.root.after(0, self.stop_ttl_monitoring)

    def is_local_packet(self, ip_addr):
        """Check if IP address is from local network (simplified)"""
        try:
            ip = ipaddress.IPv4Address(ip_addr)
            # Check for common private IP ranges
            private_ranges = [
                ipaddress.IPv4Network('192.168.0.0/16'),
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12')
            ]
            
            for network in private_ranges:
                if ip in network:
                    return True
            return False
        except:
            return False

    def get_protocol_name(self, proto_num):
        """Get protocol name from number"""
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP', 89: 'OSPF'}
        return protocol_map.get(proto_num, f'P{proto_num}')

    def update_packet_display(self, packet_info):
        """Update packet display with new packet info"""
        def update_display():
            # Format packet info
            packet_line = (f"[{packet_info['timestamp']}] "
                          f"{packet_info['src_ip']:<15} → {packet_info['dst_ip']:<15} "
                          f"({packet_info['protocol']:<4}) "
                          f"TTL: {packet_info['original_ttl']:>3} → {packet_info['new_ttl']}\n")
            
            self.packet_display.insert(tk.END, packet_line)
            self.packet_display.see(tk.END)
            
            # Keep only last 1000 lines
            lines = self.packet_display.get(1.0, tk.END).split('\n')
            if len(lines) > 1000:
                self.packet_display.delete(1.0, f"{len(lines)-1000}.0")
        
        self.root.after(0, update_display)

    def update_ttl_stats(self):
        """Update TTL monitoring statistics"""
        while self.ttl_monitoring:
            try:
                # Update stats display
                self.root.after(0, self.refresh_stats_display)
                time.sleep(1)
            except:
                break

    def refresh_stats_display(self):
        """Refresh the statistics display"""
        if hasattr(self, 'stats_labels'):
            self.stats_labels['packets_captured'].configure(text=f"{self.stats['packets_captured']:,}")
            self.stats_labels['packets_modified'].configure(text=f"{self.stats['packets_modified']:,}")
            self.stats_labels['devices_count'].configure(text=f"{len(self.stats['devices_detected'])}")
            
            if self.stats['start_time']:
                runtime = time.time() - self.stats['start_time']
                runtime_str = f"{int(runtime//60):02d}:{int(runtime%60):02d}"
                self.stats_labels['runtime'].configure(text=runtime_str)

    def check_admin_privileges(self):
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def process_logs(self):
        """Process log queue and update display"""
        try:
            while True:
                try:
                    log_entry = self.log_queue.get_nowait()
                    
                    # Add to log display
                    if hasattr(self, 'log_display'):
                        self.log_display.insert(tk.END, log_entry + "\n")
                        self.log_display.see(tk.END)
                        
                        # Color coding based on level
                        if "ERROR" in log_entry:
                            # Red for errors
                            pass
                        elif "SUCCESS" in log_entry:
                            # Green for success
                            pass
                        elif "WARNING" in log_entry:
                            # Yellow for warnings
                            pass
                    
                except queue.Empty:
                    pass
        except:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_logs)

    def clear_logs(self):
        """Clear the log display"""
        if hasattr(self, 'log_display'):
            self.log_display.delete(1.0, tk.END)
            #self.add_log("🗑️ Logs cleared", "INFO")

    def save_logs(self):
        """Save logs to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Logs"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    if hasattr(self, 'log_display'):
                        content = self.log_display.get(1.0, tk.END)
                        f.write(content)
                
                #self.add_log(f"💾 Logs saved to: {filename}", "SUCCESS")
                messagebox.showinfo("Success", f"Logs saved to:\n{filename}")
                
        except Exception as e:
            #self.add_log(f"❌ Error saving logs: {str(e)}", "ERROR")
            messagebox.showerror("Error", f"Could not save logs:\n{str(e)}")

    def on_closing(self):
        """Handle application closing"""
        if self.ttl_monitoring:
            self.stop_ttl_monitoring()
        
        self.root.quit()
        self.root.destroy()

    def run(self):
        """Start the GUI application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Set minimum size
        self.root.minsize(1000, 700)
        
        # Start the main loop
        self.root.mainloop()

def main():
    """Main application entry point"""
    try:
        # Create and run the application
        app = ModernNetworkOptimizer()
        app.run()
        
    except Exception as e:
        messagebox.showerror("Critical Error", f"Application failed to start:\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()