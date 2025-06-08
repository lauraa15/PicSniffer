#!/usr/bin/env python3
"""
Enhanced PicSniffer
Steganography Brute Force Tool with improved detection
Tool for detecting and extracting hidden messages inside an image file.
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

class EnhancedStegoBruteForcer:
    def __init__(self):
        # List of common passwords to try during brute force
        self.common_passwords = [
            "", "password", "123456", "admin", "secret", "hidden", 
            "stego", "message", "data", "file", "hack", "cyber",
            "security", "ninja", "ghost", "shadow", "darkweb", "flag"
        ]
        
        # Dictionary of steganography detection methods
        self.stego_tools = {
            'strings': self.extract_strings,
            'metadata_advanced': self.check_metadata_advanced,
            'steghide': self.try_steghide,
            'lsb': self.try_lsb_extraction,
            'file_analysis': self.analyze_file_structure
        }
        
        # Store results of analysis
        self.results = []
        
        # Common flag patterns
        self.flag_patterns = [
            r'[A-Z]{2,10}_FLAG\{[^}]+\}',  # IDN_FLAG{...}, CTF_FLAG{...}
            r'flag\{[^}]+\}',              # flag{...}
            r'FLAG\{[^}]+\}',              # FLAG{...}
            r'[A-Z]{3,}_\{[^}]+\}',       # General pattern like ABC_{...}
        ]
    
    def banner(self):
        """Display the tool's banner."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                 Enhanced PicSniffer v2.0                    ║
║                  STEGANOGRAPHY BRUTE FORCER                  ║
║                  Cybersecurity Defense Tool                  ║
║                Detect Hidden Messages in Images              ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def extract_strings(self, filepath):
        """Extract readable strings from the file (like strings command)."""
        results = []
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Extract ASCII strings (printable characters, minimum length 4)
            strings = re.findall(b'[\x20-\x7E]{4,}', content)
            
            found_flags = []
            suspicious_strings = []
            
            for string_bytes in strings:
                try:
                    string_text = string_bytes.decode('ascii')
                    
                    # Check for flag patterns
                    for pattern in self.flag_patterns:
                        matches = re.findall(pattern, string_text, re.IGNORECASE)
                        for match in matches:
                            print(f"[!] FLAG FOUND: {match}")
                            found_flags.append(match)
                    
                    # Check for suspicious keywords
                    suspicious_keywords = ['password', 'secret', 'hidden', 'flag', 'key', 'token', 'base64']
                    if len(string_text) > 10 and any(keyword in string_text.lower() for keyword in suspicious_keywords):
                        suspicious_strings.append(string_text)
                        
                except UnicodeDecodeError:
                    continue
            
            # Also check for base64-like strings
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            for string_bytes in strings:
                try:
                    string_text = string_bytes.decode('ascii')
                    b64_matches = re.findall(base64_pattern, string_text)
                    for match in b64_matches:
                        if len(match) > 20:  # Reasonable base64 length
                            try:
                                import base64
                                decoded = base64.b64decode(match + '==')  # Add padding
                                decoded_text = decoded.decode('ascii', errors='ignore')
                                if len(decoded_text) > 4 and decoded_text.isprintable():
                                    print(f"[?] Possible Base64: {match[:50]}...")
                                    print(f"[?] Decoded: {decoded_text[:100]}...")
                                    suspicious_strings.append(f"Base64: {decoded_text}")
                            except:
                                pass
                except:
                    continue
            
            if found_flags or suspicious_strings:
                results = {
                    'flags': found_flags,
                    'suspicious_strings': suspicious_strings[:10]  # Limit output
                }
                
                print(f"[!] String analysis found {len(found_flags)} flags and {len(suspicious_strings)} suspicious strings")
                return results
            
        except Exception as e:
            print(f"[-] Error in string extraction: {e}")
        
        return None
    
    def check_metadata_advanced(self, filepath):
        """Advanced metadata checking using PIL and raw data."""
        try:
            img = Image.open(filepath)
            suspicious_metadata = []
            
            # Get all EXIF data with proper tag names
            exif_dict = img._getexif()
            if exif_dict:
                for tag_id, value in exif_dict.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    
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
                        # Check for flags in image info
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, value, re.IGNORECASE)
                            for match in matches:
                                print(f"[!] FLAG IN IMAGE INFO: {match}")
                                suspicious_metadata.append(f"FLAG in {key}: {match}")
            
            if suspicious_metadata:
                print(f"[!] Advanced metadata analysis found {len(suspicious_metadata)} items")
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
            
            # Look for multiple file signatures (file within file)
            signatures = {
                b'\xFF\xD8\xFF': 'JPEG',
                b'\x89PNG': 'PNG', 
                b'GIF8': 'GIF',
                b'PK\x03\x04': 'ZIP',
                b'Rar!': 'RAR',
                b'\x1f\x8b': 'GZIP'
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
            
            if found_signatures:
                print(f"[!] Multiple file signatures detected: {found_signatures}")
                return {'multiple_signatures': found_signatures}
                
        except Exception as e:
            print(f"[-] Error in file structure analysis: {e}")
        
        return None
    
    def try_steghide(self, filepath):
        """Attempt to extract hidden data using steghide with common passwords."""
        results = []
        
        # Check if steghide is available
        try:
            subprocess.run(['steghide', '--version'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[-] Steghide not found, skipping steghide analysis")
            return None
        
        for password in self.common_passwords:
            try:
                # Create a temporary file for output
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp_path = tmp.name
                
                # Steghide command
                cmd = ['steghide', 'extract', '-sf', filepath, '-xf', tmp_path]
                if password:
                    cmd.extend(['-p', password])
                else:
                    cmd.extend(['-p', ''])
                
                # Execute steghide
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    # Successfully extracted data
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
                            pass
                        
                        results.append({
                            'password': password,
                            'size': len(content),
                            'content_preview': content[:100]
                        })
                
                # Cleanup temporary file
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                continue
        
        return results if results else None
    
    def try_lsb_extraction(self, filepath):
        """Enhanced LSB extraction with better text detection."""
        try:
            img = Image.open(filepath)
            
            # Convert to RGB if not already in that mode
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get pixel data
            pixels = list(img.getdata())
            
            # Extract LSB from each channel (more pixels this time)
            binary_data = []
            
            for pixel in pixels[:min(5000, len(pixels))]:  # Test more pixels
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
                            # Don't break immediately, might be binary data
                            if len(text_data) > 0:
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
            if len(text_data) > 10 and any(c.isalpha() for c in text_data):
                print(f"[!] Possible LSB steganography detected!")
                print(f"[!] Sample text: {text_data[:100]}...")
                return {'method': 'LSB', 'sample': text_data[:200]}
                
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
        
        print(f"[i] File size: {file_size} bytes")
        print(f"[i] File hash (MD5): {file_hash}")
        
        # Try different steganography detection methods
        suspicious = False
        
        for method_name, method_func in self.stego_tools.items():
            print(f"\n[*] Testing method: {method_name.upper()}")
            result = method_func(filepath)
            if result:
                suspicious = True
                self.results.append({
                    'file': filepath,
                    'method': method_name,
                    'result': result
                })
        
        return suspicious
    
    def get_file_hash(self, filepath):
        """Generate MD5 hash for the file."""
        hash_md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def generate_report(self):
        """Generate a report of the analysis results."""
        if not self.results:
            print("\n[i] No hidden messages detected with current methods.")
            return
        
        print("\n" + "="*60)
        print("ENHANCED STEGANOGRAPHY ANALYSIS REPORT")
        print("="*60)
        
        flags_found = []
        for i, result in enumerate(self.results, 1):
            print(f"\n[{i}] File: {result['file']}")
            print(f"    Method: {result['method']}")
            print(f"    Details: {result['result']}")
            
            # Collect flags
            if isinstance(result['result'], dict):
                if 'flags' in result['result']:
                    flags_found.extend(result['result']['flags'])
                if 'flag' in result['result']:
                    flags_found.append(result['result']['flag'])
                if 'trailing_flag' in result['result']:
                    flags_found.append(result['result']['trailing_flag'])
        
        if flags_found:
            print(f"\n{'='*20} FLAGS DISCOVERED {'='*20}")
            for flag in set(flags_found):  # Remove duplicates
                print(f"🚩 {flag}")
            print("="*60)
        
        print(f"\n[!] Total suspicious detections: {len(self.results)}")
        print("[!] Manual verification recommended for all detections.")

def main():
    parser = argparse.ArgumentParser(description='Enhanced Steganography Brute Force Tool')
    parser.add_argument('file', help='Image file to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize tool
    stego_tool = EnhancedStegoBruteForcer()
    stego_tool.banner()
    
    # Analyze file
    suspicious = stego_tool.analyze_file(args.file)
    
    # Generate report
    stego_tool.generate_report()
    
    if suspicious:
        print(f"\n[!] WARNING: File may contain hidden data!")
        print("[!] Recommend further manual analysis.")
    else:
        print(f"\n[+] File appears clean (no steganography detected)")

if __name__ == "__main__":
    main()
