#!/usr/bin/env python3
"""
Enhanced PicSniffer v3.0
Advanced Steganography Brute Force Tool
Tool for detecting and extracting hidden messages inside image files.
Made for cybersecurity defense and educational purposes.
"""

import os
import sys
import argparse
from PIL import Image
from PIL.ExifTags import TAGS
import numpy as np
import subprocess
import tempfile
import hashlib
import re
from pathlib import Path
import json
import time
import shutil

class EnhancedStegoBruteForcer:
    def __init__(self):
        # List of common passwords to try during brute force
        self.common_passwords = [
            "", "password", "123456", "admin", "secret", "hidden", 
            "stego", "message", "data", "file", "hack", "cyber",
            "security", "ninja", "ghost", "shadow", "darkweb", "flag",
            "ctf", "challenge", "key", "pass", "unlock", "decode",
            "steganography", "image", "picture", "photo", "jpeg", "png"
        ]
        
        # Dictionary of steganography detection methods
        self.stego_tools = {
            'exiftool': self.run_exiftool_analysis,
            'strings_enhanced': self.extract_strings_enhanced,
            'stegseek': self.try_stegseek,
            'steghide': self.try_steghide_enhanced,
            'metadata_advanced': self.check_metadata_advanced,
            'lsb': self.try_lsb_extraction,
            'file_analysis': self.analyze_file_structure,
            'binwalk': self.try_binwalk,
            'zsteg': self.try_zsteg
        }
        
        # Store results of analysis
        self.results = []
        
        # Common flag patterns
        self.flag_patterns = [
            r'[A-Z]{2,10}_FLAG\{[^}]+\}',  # IDN_FLAG{...}, CTF_FLAG{...}
            r'flag\{[^}]+\}',              # flag{...}
            r'FLAG\{[^}]+\}',              # FLAG{...}
            r'[A-Z]{3,}_\{[^}]+\}',       # General pattern like ABC_{...}
            r'CTF\{[^}]+\}',              # CTF{...}
            r'DUCTF\{[^}]+\}',            # DUCTF{...}
            r'picoCTF\{[^}]+\}',          # picoCTF{...}
        ]
        
        # Common wordlists for stegseek
        self.wordlists = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/fasttrack.txt',
            '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
            '/usr/share/seclists/Passwords/darkweb2017-top10000.txt',
            './wordlist.txt',
            './passwords.txt'
        ]
    
    def banner(self):
        """Display the tool's banner."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                 Enhanced PicSniffer v3.0                    ║
║              ADVANCED STEGANOGRAPHY BRUTE FORCER            ║
║                  Cybersecurity Defense Tool                  ║
║                Detect Hidden Messages in Images              ║
║        Supports: ExifTool, Stegseek, Steghide, Binwalk      ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def check_dependencies(self):
        """Check if required tools are installed."""
        tools = {
            'exiftool': 'exiftool',
            'stegseek': 'stegseek',
            'steghide': 'steghide',
            'binwalk': 'binwalk',
            'zsteg': 'zsteg',
            'strings': 'strings'
        }
        
        available_tools = {}
        
        for tool_name, command in tools.items():
            try:
                result = subprocess.run([command, '--version'], 
                                      capture_output=True, timeout=5)
                available_tools[tool_name] = True
                print(f"[+] {tool_name}: Available")
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
                available_tools[tool_name] = False
                print(f"[-] {tool_name}: Not found")
        
        return available_tools
    
    def run_exiftool_analysis(self, filepath):
        """Run exiftool analysis and check for suspicious metadata."""
        try:
            # Run exiftool command
            result = subprocess.run(['exiftool', '-j', filepath], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"[-] ExifTool failed: {result.stderr}")
                return None
            
            # Parse JSON output
            try:
                exif_data = json.loads(result.stdout)[0]
            except (json.JSONDecodeError, IndexError):
                print("[-] Failed to parse ExifTool output")
                return None
            
            print("\n[+] EXIFTOOL ANALYSIS:")
            print("="*50)
            
            suspicious_fields = []
            flags_found = []
            
            # Display all metadata first
            for key, value in exif_data.items():
                if key not in ['SourceFile', 'ExifTool:ExifToolVersion']:
                    print(f"{key}: {value}")
                    
                    # Check for flags and suspicious content
                    value_str = str(value)
                    
                    # Check for flag patterns
                    for pattern in self.flag_patterns:
                        matches = re.findall(pattern, value_str, re.IGNORECASE)
                        for match in matches:
                            print(f"[!] FLAG FOUND IN METADATA: {match}")
                            flags_found.append(match)
                    
                    # Check for suspicious keywords
                    suspicious_keywords = ['flag', 'secret', 'hidden', 'password', 'key', 
                                         'stego', 'base64', 'encoded', 'cipher']
                    if any(keyword in value_str.lower() for keyword in suspicious_keywords):
                        suspicious_fields.append(f"{key}: {value}")
            
            print("="*50)
            
            # Check for unusual or modified fields
            unusual_fields = []
            common_fields = ['FileName', 'Directory', 'FileSize', 'FileModifyDate', 
                           'FileAccessDate', 'FilePermissions', 'FileType', 'MIMEType']
            
            for key in exif_data.keys():
                if key not in common_fields and 'ExifTool' not in key:
                    unusual_fields.append(f"{key}: {exif_data[key]}")
            
            if flags_found or suspicious_fields or unusual_fields:
                return {
                    'flags': flags_found,
                    'suspicious_fields': suspicious_fields,
                    'unusual_fields': unusual_fields,
                    'all_metadata': exif_data
                }
            
        except Exception as e:
            print(f"[-] Error in ExifTool analysis: {e}")
        
        return None
    
    def extract_strings_enhanced(self, filepath):
        """Enhanced string extraction with better pattern matching."""
        results = []
        
        try:
            # Use system strings command if available
            try:
                result = subprocess.run(['strings', '-n', '4', filepath], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    all_strings = result.stdout.split('\n')
                else:
                    raise FileNotFoundError
            except (FileNotFoundError, subprocess.CalledProcessError):
                # Fallback to manual extraction
                with open(filepath, 'rb') as f:
                    content = f.read()
                
                # Extract ASCII strings (printable characters, minimum length 4)
                string_matches = re.findall(b'[\x20-\x7E]{4,}', content)
                all_strings = [s.decode('ascii', errors='ignore') for s in string_matches]
            
            print(f"\n[+] STRINGS ANALYSIS - Found {len(all_strings)} strings")
            print("="*50)
            
            found_flags = []
            suspicious_strings = []
            bracket_strings = []
            
            for string_text in all_strings:
                if not string_text.strip():
                    continue
                
                # Check for flag patterns
                for pattern in self.flag_patterns:
                    matches = re.findall(pattern, string_text, re.IGNORECASE)
                    for match in matches:
                        print(f"[!] FLAG FOUND: {match}")
                        found_flags.append(match)
                
                # Extract strings with brackets as requested
                if '{' in string_text and '}' in string_text:
                    # Get 10 chars before opening bracket
                    bracket_matches = re.finditer(r'(.{0,10})\{([^}]*)\}', string_text)
                    for match in bracket_matches:
                        before = match.group(1)
                        inside = match.group(2)
                        bracket_string = f"{before}{{{inside}}}"
                        bracket_strings.append(bracket_string)
                        print(f"[?] Bracket pattern: {bracket_string}")
                
                # Check for suspicious keywords
                suspicious_keywords = ['password', 'secret', 'hidden', 'flag', 'key', 'token', 
                                     'base64', 'stego', 'cipher', 'encoded', 'decrypt']
                if len(string_text) > 10 and any(keyword in string_text.lower() for keyword in suspicious_keywords):
                    suspicious_strings.append(string_text)
                    print(f"[?] Suspicious: {string_text[:100]}...")
            
            # Check for base64-like strings
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            for string_text in all_strings:
                b64_matches = re.findall(base64_pattern, string_text)
                for match in b64_matches:
                    if len(match) > 20:
                        try:
                            import base64
                            decoded = base64.b64decode(match + '==')
                            decoded_text = decoded.decode('ascii', errors='ignore')
                            if len(decoded_text) > 4 and decoded_text.isprintable():
                                print(f"[?] Possible Base64: {match[:50]}...")
                                print(f"[?] Decoded: {decoded_text[:100]}...")
                                suspicious_strings.append(f"Base64: {decoded_text}")
                        except:
                            pass
            
            print("="*50)
            
            if found_flags or suspicious_strings or bracket_strings:
                return {
                    'flags': found_flags,
                    'suspicious_strings': suspicious_strings[:20],
                    'bracket_patterns': bracket_strings[:20]
                }
                
        except Exception as e:
            print(f"[-] Error in string extraction: {e}")
        
        return None
    
    def try_stegseek(self, filepath):
        """Try stegseek with available wordlists."""
        try:
            # Check if stegseek is available
            subprocess.run(['stegseek', '--version'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[-] Stegseek not found, skipping stegseek analysis")
            return None
        
        print(f"\n[+] STEGSEEK ANALYSIS:")
        print("="*50)
        
        results = []
        
        # Find available wordlists
        available_wordlists = []
        for wordlist in self.wordlists:
            if os.path.exists(wordlist):
                available_wordlists.append(wordlist)
                print(f"[+] Found wordlist: {wordlist}")
        
        if not available_wordlists:
            print("[-] No wordlists found, creating basic wordlist...")
            # Create a basic wordlist
            basic_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            for password in self.common_passwords:
                basic_wordlist.write(password + '\n')
            basic_wordlist.close()
            available_wordlists.append(basic_wordlist.name)
        
        # Try stegseek with each wordlist
        for wordlist in available_wordlists[:2]:  # Limit to first 2 wordlists to avoid timeout
            try:
                print(f"[*] Trying wordlist: {os.path.basename(wordlist)}")
                
                # Create temporary output file
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    output_file = tmp.name
                
                # Run stegseek
                cmd = ['stegseek', filepath, wordlist, output_file]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    # Success - found password
                    print(f"[!] STEGSEEK SUCCESS!")
                    print(result.stdout)
                    
                    # Read extracted content
                    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                        with open(output_file, 'rb') as f:
                            content = f.read()
                        
                        print(f"[!] Extracted {len(content)} bytes")
                        
                        # Check for flags
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            for pattern in self.flag_patterns:
                                matches = re.findall(pattern, text_content, re.IGNORECASE)
                                if matches:
                                    print(f"[!] FLAG IN STEGSEEK DATA: {matches[0]}")
                            
                            if text_content.isprintable():
                                print(f"[!] Content preview: {text_content[:200]}...")
                        except:
                            print(f"[!] Binary content extracted (first 100 bytes): {content[:100]}")
                        
                        results.append({
                            'wordlist': wordlist,
                            'size': len(content),
                            'content_preview': content[:200]
                        })
                
                # Cleanup
                if os.path.exists(output_file):
                    os.unlink(output_file)
                    
            except subprocess.TimeoutExpired:
                print(f"[-] Stegseek timed out with {wordlist}")
                continue
            except Exception as e:
                print(f"[-] Error with stegseek: {e}")
                continue
        
        print("="*50)
        return results if results else None
    
    def try_steghide_enhanced(self, filepath):
        """Enhanced steghide analysis with filename-based passwords."""
        try:
            subprocess.run(['steghide', '--version'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[-] Steghide not found, skipping steghide analysis")
            return None
        
        print(f"\n[+] STEGHIDE ANALYSIS:")
        print("="*50)
        
        results = []
        
        # Get filename-based passwords
        filename = os.path.basename(filepath)
        filename_no_ext = os.path.splitext(filename)[0]
        
        # Extended password list including filename variations
        extended_passwords = self.common_passwords + [
            filename,
            filename_no_ext,
            filename.lower(),
            filename_no_ext.lower(),
            filename.upper(),
            filename_no_ext.upper()
        ]
        
        for password in extended_passwords:
            try:
                print(f"[*] Trying password: '{password}'", end=' ... ')
                
                # Create temporary output file
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp_path = tmp.name
                
                # Steghide command
                cmd = ['steghide', 'extract', '-sf', filepath, '-xf', tmp_path]
                if password:
                    cmd.extend(['-p', password])
                else:
                    cmd.extend(['-p', ''])
                
                # Execute steghide
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    print("SUCCESS!")
                    if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                        with open(tmp_path, 'rb') as f:
                            content = f.read()
                        
                        print(f"[!] STEGHIDE SUCCESS! Password: '{password}'")
                        print(f"[!] Extracted {len(content)} bytes")
                        
                        # Check for flags in extracted content
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            for pattern in self.flag_patterns:
                                matches = re.findall(pattern, text_content, re.IGNORECASE)
                                if matches:
                                    print(f"[!] FLAG IN STEGHIDE DATA: {matches[0]}")
                            
                            if text_content.isprintable():
                                print(f"[!] Content preview: {text_content[:200]}...")
                        except:
                            print(f"[!] Binary content (first 50 bytes): {content[:50]}")
                        
                        results.append({
                            'password': password,
                            'size': len(content),
                            'content_preview': content[:100]
                        })
                else:
                    print("Failed")
                
                # Cleanup temporary file
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
            except subprocess.TimeoutExpired:
                print("Timeout")
                continue
            except Exception as e:
                print(f"Error: {e}")
                continue
        
        print("="*50)
        return results if results else None
    
    def try_binwalk(self, filepath):
        """Try binwalk analysis for embedded files."""
        try:
            subprocess.run(['binwalk', '--version'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[-] Binwalk not found, skipping binwalk analysis")
            return None
        
        print(f"\n[+] BINWALK ANALYSIS:")
        print("="*50)
        
        try:
            # Run binwalk
            result = subprocess.run(['binwalk', filepath], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.stdout:
                print(result.stdout)
                
                # Check if multiple files were found
                lines = result.stdout.split('\n')
                embedded_files = [line for line in lines if line.strip() and not line.startswith('DECIMAL')]
                
                if len(embedded_files) > 1:
                    print(f"[!] Found {len(embedded_files)} embedded files/signatures")
                    return {'embedded_files': embedded_files}
            
        except Exception as e:
            print(f"[-] Error in binwalk analysis: {e}")
        
        print("="*50)
        return None
    
    def try_zsteg(self, filepath):
        """Try zsteg analysis (for PNG files mainly)."""
        try:
            subprocess.run(['zsteg', '--version'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[-] Zsteg not found, skipping zsteg analysis")
            return None
        
        # Check if file is PNG (zsteg works best with PNG)
        if not filepath.lower().endswith('.png'):
            return None
        
        print(f"\n[+] ZSTEG ANALYSIS (PNG):")
        print("="*50)
        
        try:
            # Run zsteg
            result = subprocess.run(['zsteg', filepath], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.stdout:
                print(result.stdout)
                
                # Check for flags in zsteg output
                for pattern in self.flag_patterns:
                    matches = re.findall(pattern, result.stdout, re.IGNORECASE)
                    if matches:
                        print(f"[!] FLAG IN ZSTEG OUTPUT: {matches[0]}")
                        return {'method': 'zsteg', 'flag': matches[0]}
                
                # Check for meaningful text
                lines = result.stdout.split('\n')
                meaningful_lines = [line for line in lines if line.strip() and 'text:' in line.lower()]
                if meaningful_lines:
                    return {'method': 'zsteg', 'findings': meaningful_lines}
            
        except Exception as e:
            print(f"[-] Error in zsteg analysis: {e}")
        
        print("="*50)
        return None
    
    def check_metadata_advanced(self, filepath):
        """Advanced metadata checking using PIL and raw data."""
        try:
            img = Image.open(filepath)
            suspicious_metadata = []
            
            print(f"\n[+] PIL METADATA ANALYSIS:")
            print("="*50)
            
            # Get all EXIF data with proper tag names
            exif_dict = img._getexif()
            if exif_dict:
                for tag_id, value in exif_dict.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    print(f"{tag_name}: {value}")
                    
                    if isinstance(value, (str, bytes)):
                        value_str = str(value)
                        
                        # Check for flag patterns in metadata
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, value_str, re.IGNORECASE)
                            for match in matches:
                                print(f"[!] FLAG IN METADATA: {match}")
                                suspicious_metadata.append(f"FLAG in {tag_name}: {match}")
                        
                        # Check for suspicious content
                        suspicious_keywords = ['flag', 'secret', 'hidden', 'password', 'key']
                        if any(keyword in value_str.lower() for keyword in suspicious_keywords):
                            suspicious_metadata.append(f"{tag_name}: {value_str}")
            
            # Check image info/comments
            if hasattr(img, 'info'):
                for key, value in img.info.items():
                    if isinstance(value, str):
                        print(f"{key}: {value}")
                        # Check for flags in image info
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, value, re.IGNORECASE)
                            for match in matches:
                                print(f"[!] FLAG IN IMAGE INFO: {match}")
                                suspicious_metadata.append(f"FLAG in {key}: {match}")
            
            print("="*50)
            
            if suspicious_metadata:
                return {'metadata': suspicious_metadata}
                
        except Exception as e:
            print(f"[-] Error in advanced metadata check: {e}")
        
        return None
    
    def analyze_file_structure(self, filepath):
        """Analyze file structure for hidden data appended to the end."""
        try:
            # Read the entire file
            with open(filepath, 'rb') as f:
                content = f.read()
            
            print(f"\n[+] FILE STRUCTURE ANALYSIS:")
            print("="*50)
            
            # Look for multiple file signatures (file within file)
            signatures = {
                b'\xFF\xD8\xFF': 'JPEG',
                b'\x89PNG': 'PNG', 
                b'GIF8': 'GIF',
                b'PK\x03\x04': 'ZIP',
                b'Rar!': 'RAR',
                b'\x1f\x8b': 'GZIP',
                b'BM': 'BMP',
                b'%PDF': 'PDF'
            }
            
            found_signatures = []
            for sig, file_type in signatures.items():
                positions = []
                start = 0
                while True:
                    pos = content.find(sig, start)
                    if pos == -1:
                        break
                    positions.append(pos)
                    start = pos + 1
                
                if len(positions) > 1:  # Multiple occurrences
                    found_signatures.append(f"{file_type}: {len(positions)} occurrences at {positions}")
                    print(f"[!] Multiple {file_type} signatures found: {positions}")
            
            # Check for data after normal image end
            img = Image.open(filepath)
            img_format = img.format.lower()
            
            # For JPEG, look for data after FFD9
            if img_format == 'jpeg':
                jpeg_end = content.rfind(b'\xFF\xD9')
                if jpeg_end != -1 and jpeg_end < len(content) - 2:
                    trailing_data = content[jpeg_end + 2:]
                    if len(trailing_data) > 10:
                        print(f"[!] Found {len(trailing_data)} bytes after JPEG end marker")
                        
                        # Check if trailing data contains flags
                        trailing_str = trailing_data.decode('ascii', errors='ignore')
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, trailing_str, re.IGNORECASE)
                            if matches:
                                print(f"[!] FLAG IN TRAILING DATA: {matches[0]}")
                                return {'trailing_flag': matches[0], 'trailing_size': len(trailing_data)}
                        
                        return {'trailing_data': len(trailing_data)}
            
            print("="*50)
            
            if found_signatures:
                return {'multiple_signatures': found_signatures}
                
        except Exception as e:
            print(f"[-] Error in file structure analysis: {e}")
        
        return None
    
    def try_lsb_extraction(self, filepath):
        """Enhanced LSB extraction with better text detection."""
        try:
            img = Image.open(filepath)
            
            print(f"\n[+] LSB STEGANOGRAPHY ANALYSIS:")
            print("="*50)
            
            # Convert to RGB if not already in that mode
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get pixel data
            pixels = list(img.getdata())
            
            # Extract LSB from each channel (more pixels this time)
            binary_data = []
            
            for pixel in pixels[:min(10000, len(pixels))]:  # Test more pixels
                r, g, b = pixel
                binary_data.append(str(r & 1))
                binary_data.append(str(g & 1))
                binary_data.append(str(b & 1))
            
            # Convert binary to text
            binary_string = ''.join(binary_data)
            
            # Try to find readable text patterns
            text_data = ""
            for i in range(0, len(binary_string)-8, 8):
                byte = binary_string[i:i+8]
                if len(byte) == 8:
                    try:
                        char = chr(int(byte, 2))
                        if 32 <= ord(char) <= 126:  # Printable ASCII
                            text_data += char
                        else:
                            # Check if we have enough meaningful text
                            if len(text_data) > 20:
                                break
                    except:
                        break
            
            # Check for flags in LSB data
            if len(text_data) > 5:
                for pattern in self.flag_patterns:
                    matches = re.findall(pattern, text_data, re.IGNORECASE)
                    if matches:
                        print(f"[!] FLAG IN LSB DATA: {matches[0]}")
                        return {'method': 'LSB', 'flag': matches[0], 'sample': text_data[:200]}
            
            # Check if we found meaningful text
            if len(text_data) > 20 and any(c.isalpha() for c in text_data):
                print(f"[!] Possible LSB steganography detected!")
                print(f"[!] Sample text: {text_data[:150]}...")
                return {'method': 'LSB', 'sample': text_data[:200]}
            
            print("[-] No meaningful LSB data found")
            print("="*50)
                
        except Exception as e:
            print(f"[-] Error in LSB analysis: {e}")
        
        return None
    
    def analyze_file(self, filepath):
        """Main analysis function for image files."""
        print(f"[+] Analyzing file: {filepath}")
        
        if not os.path.exists(filepath):
            print(f"[-] File not found: {filepath}")
            return False
        
        # Basic file information
        file_size = os.path.getsize(filepath)
        file_hash = self.get_file_hash(filepath)
        
        print(f"[i] File size: {file_size:,} bytes")
        print(f"[i] File hash (MD5): {file_hash}")
        
        # Check available tools
        print(f"\n[+] Checking available tools...")
        available_tools = self.check_dependencies()
        
        # Try different steganography detection methods
        suspicious = False
        
        for method_name, method_func in self.stego_tools.items():
            # Skip methods where tools are not available
            if method_name in available_tools and not available_tools[method_name]:
                continue
                
            print(f"\n{'='*60}")
            print(f"[*] Testing method: {method_name.upper()}")
            print(f"{'='*60}")
            
            try:
                result = method_func(filepath)
                if result:
                    suspicious = True
                    self.results.append({
                        'file': filepath,
                        'method': method_name,
                        'result': result
                    })
            except Exception as e:
                print(f"[-] Error in {method_name}: {e}")
        
        return suspicious
    
    def get_file_hash(self, filepath):
        """Generate MD5 hash for the file."""
        hash_md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def generate_report(self):
        """Generate a comprehensive report of the analysis results."""
        if not self.results:
            print("\n" + "="*60)
            print("ANALYSIS COMPLETE - NO HIDDEN MESSAGES DETECTED")
            print("="*60)
            print("[i] No hidden messages detected with current methods.")
            print("[i] This doesn't guarantee the file is clean - manual analysis recommended.")
            return
        
        print("\n" + "="*80)
        print("ENHANCED STEGANOGRAPHY ANALYSIS REPORT")
        print("="*80)
        
        flags_found = []
        all_findings = {}
        
        for i, result in enumerate(self.results, 1):
            method = result['method'].upper()
            print(f"\n[{i}] METHOD: {method}")
            print("-" * 50)
            print(f"    File: {result['file']}")
            print(f"    Details: {result['result']}")
            
            # Collect flags
            if isinstance(result['result'], dict):
                if 'flags' in result['result']:
                    flags_found.extend(result['result']['flags'])
                if 'flag' in result['result']:
                    flags_found.append(result['result']['flag'])
                if 'trailing_flag' in result['result']:
                    flags_found.append(result['result']['trailing_flag'])
                
                # Store findings by method
                all_findings[method] = result['result']
        
        # Display discovered flags prominently
        if flags_found:
            print(f"\n{'='*25} FLAGS DISCOVERED {'='*25}")
            unique_flags = list(set(flags_found))  # Remove duplicates
            for i, flag in enumerate(unique_flags, 1):
                print(f"🚩 [{i}] {flag}")
            print("="*70)
        
        # Summary statistics
        print(f"\n{'='*25} ANALYSIS SUMMARY {'='*25}")
        print(f"Total detection methods used: {len(self.stego_tools)}")
        print(f"Suspicious detections found: {len(self.results)}")
        print(f"Unique flags discovered: {len(set(flags_found))}")
        print(f"Methods with findings: {', '.join(all_findings.keys())}")
        
        # Recommendations
        print(f"\n{'='*25} RECOMMENDATIONS {'='*25}")
        if flags_found:
            print("🔴 HIGH RISK: Flags detected in image!")
            print("   → This image definitely contains hidden data")
            print("   → Document all discovered flags")
            print("   → Investigate source and context")
        elif len(self.results) > 0:
            print("🟡 MEDIUM RISK: Suspicious patterns detected")
            print("   → Manual verification recommended")
            print("   → Consider additional analysis tools")
            print("   → Check with different wordlists/passwords")
        else:
            print("🟢 LOW RISK: No obvious steganography detected")
            print("   → File appears clean with current methods")
            print("   → Advanced techniques may still be present")
        
        print("="*70)
        
        # Save detailed report to file
        self.save_detailed_report(all_findings, flags_found)
    
    def save_detailed_report(self, findings, flags):
        """Save detailed analysis report to a file."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_filename = f"stego_analysis_report_{timestamp}.txt"
        
        try:
            with open(report_filename, 'w') as f:
                f.write("ENHANCED STEGANOGRAPHY ANALYSIS REPORT\n")
                f.write("="*50 + "\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Tool: Enhanced PicSniffer v3.0\n\n")
                
                if flags:
                    f.write("DISCOVERED FLAGS:\n")
                    f.write("-"*20 + "\n")
                    for flag in set(flags):
                        f.write(f"• {flag}\n")
                    f.write("\n")
                
                f.write("DETAILED FINDINGS:\n")
                f.write("-"*20 + "\n")
                for method, result in findings.items():
                    f.write(f"\n{method}:\n")
                    f.write(f"  {result}\n")
                
                f.write(f"\nTotal detections: {len(findings)}\n")
                f.write(f"Unique flags: {len(set(flags))}\n")
            
            print(f"[+] Detailed report saved to: {report_filename}")
            
        except Exception as e:
            print(f"[-] Failed to save report: {e}")

def print_installation_guide():
    """Print installation guide for required tools."""
    print("""
INSTALLATION GUIDE FOR STEGANOGRAPHY TOOLS
==========================================

1. EXIFTOOL:
   Ubuntu/Debian: sudo apt install exiftool
   macOS: brew install exiftool
   
2. STEGSEEK (Faster steghide cracker):
   wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb
   sudo dpkg -i stegseek_0.6-1.deb
   sudo apt-get install -f  # Fix dependencies if needed
   
3. STEGHIDE:
   Ubuntu/Debian: sudo apt install steghide
   macOS: brew install steghide
   
4. BINWALK:
   Ubuntu/Debian: sudo apt install binwalk
   macOS: brew install binwalk
   
5. ZSTEG (Ruby gem for PNG/BMP):
   sudo gem install zsteg
   
6. COMMON WORDLISTS:
   sudo apt install seclists
   sudo apt install wordlists
   # Or download rockyou.txt manually
   
EXAMPLE USAGE:
python3 enhanced_picsniffer.py image.jpg
python3 enhanced_picsniffer.py image.png -v
    """)

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Steganography Brute Force Tool v3.0',
        epilog='Example: python3 %(prog)s suspicious_image.jpg'
    )
    parser.add_argument('file', help='Image file to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose output (currently unused)')
    parser.add_argument('--install-guide', action='store_true',
                       help='Show installation guide for required tools')
    
    args = parser.parse_args()
    
    if args.install_guide:
        print_installation_guide()
        return
    
    # Initialize tool
    stego_tool = EnhancedStegoBruteForcer()
    stego_tool.banner()
    
    # Check if file exists and is readable
    if not os.path.exists(args.file):
        print(f"[-] Error: File '{args.file}' not found!")
        sys.exit(1)
    
    if not os.access(args.file, os.R_OK):
        print(f"[-] Error: Cannot read file '{args.file}'!")
        sys.exit(1)
    
    # Verify it's an image file
    try:
        with Image.open(args.file) as img:
            print(f"[+] Image format: {img.format}")
            print(f"[+] Image size: {img.size}")
            print(f"[+] Image mode: {img.mode}")
    except Exception as e:
        print(f"[-] Warning: Could not open as image file: {e}")
        print("[i] Continuing with raw file analysis...")
    
    print(f"\n[+] Starting analysis of: {args.file}")
    start_time = time.time()
    
    # Analyze file
    try:
        suspicious = stego_tool.analyze_file(args.file)
        
        # Generate report
        stego_tool.generate_report()
        
        # Final summary
        end_time = time.time()
        analysis_time = end_time - start_time
        
        print(f"\n{'='*60}")
        print(f"ANALYSIS COMPLETED IN {analysis_time:.2f} SECONDS")
        print(f"{'='*60}")
        
        if suspicious:
            print(f"🔴 RESULT: SUSPICIOUS - Hidden data detected!")
            print(f"[!] Recommend immediate investigation")
            sys.exit(2)  # Exit code 2 for suspicious files
        else:
            print(f"🟢 RESULT: Clean - No obvious steganography detected")
            print(f"[i] File appears clean with current analysis methods")
            sys.exit(0)  # Exit code 0 for clean files
            
    except KeyboardInterrupt:
        print(f"\n[!] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Fatal error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
