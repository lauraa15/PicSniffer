#!/usr/bin/env python3
"""
PicSniffer
Steganography Brute Force Tool
Tool for detecting and extracting hidden messages inside an image file.
Made for cybersecurity defense and educational purposes.
"""

import os
import sys
import argparse
from PIL import Image
import numpy as np
import subprocess
import tempfile
import hashlib
from pathlib import Path

class StegoBruteForcer:
    def __init__(self):
        # List of common passwords to try during brute force
        self.common_passwords = [
            "", "password", "123456", "admin", "secret", "hidden", 
            "stego", "message", "data", "file", "hack", "cyber",
            "security", "ninja", "ghost", "shadow", "darkweb"
        ]
        
        # Dictionary of steganography detection methods
        self.stego_tools = {
            'steghide': self.try_steghide,
            'lsb': self.try_lsb_extraction,
            'metadata': self.check_metadata
        }
        
        # Store results of analysis
        self.results = []
    
    def banner(self):
        """Display the tool's banner."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    ______PicSniffer______                    ║
║                  STEGANOGRAPHY BRUTE FORCER                  ║
║                  Cybersecurity Defense Tool                  ║
║                Detect Hidden Messages in Images              ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
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
    
    def try_steghide(self, filepath):
        """Attempt to extract hidden data using steghide with common passwords."""
        results = []
        
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
                        
                        print(f"[!] FOUND with steghide! Password: '{password}'")
                        print(f"[!] Extracted {len(content)} bytes")
                        
                        # Try to decode as text
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            if len(text_content) > 0 and text_content.isprintable():
                                print(f"[!] Content preview: {text_content[:100]}...")
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
                print(f"[!] Timeout testing password: '{password}'")
                continue
            except Exception as e:
                continue
        
        return results if results else None
    
    def try_lsb_extraction(self, filepath):
        """Attempt to detect LSB (Least Significant Bit) steganography."""
        try:
            img = Image.open(filepath)
            
            # Convert to RGB if not already in that mode
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get pixel data
            pixels = list(img.getdata())
            
            # Extract LSB from each channel
            binary_data = []
            
            for pixel in pixels[:1000]:  # Test first 1000 pixels
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
                        if char.isprintable():
                            text_data += char
                        else:
                            break
                    except:
                        break
            
            # Check if we found meaningful text
            if len(text_data) > 10 and any(c.isalpha() for c in text_data):
                print(f"[!] Possible LSB steganography detected!")
                print(f"[!] Sample text: {text_data[:50]}...")
                return {'method': 'LSB', 'sample': text_data[:100]}
            
            # Statistical analysis
            bit_frequency = binary_data.count('1') / len(binary_data)
            if abs(bit_frequency - 0.5) < 0.01:  # Very close to 50/50
                print(f"[?] Suspicious bit distribution (LSB): {bit_frequency:.4f}")
                return {'method': 'LSB_statistical', 'bit_freq': bit_frequency}
                
        except Exception as e:
            print(f"[-] Error in LSB analysis: {e}")
        
        return None
    
    def check_metadata(self, filepath):
        """Check image metadata for hidden data."""
        try:
            img = Image.open(filepath)
            
            # Get EXIF data
            exif_data = img._getexif()
            suspicious_metadata = []
            
            if exif_data:
                for tag_id, value in exif_data.items():
                    if isinstance(value, str):
                        # Check for suspicious strings
                        if any(keyword in value.lower() for keyword in ['http', 'ftp', 'password', 'hidden', 'secret']):
                            suspicious_metadata.append(f"Tag {tag_id}: {value}")
            
            # Check file size vs expected size
            width, height = img.size
            expected_size = width * height * 3  # RGB
            actual_size = os.path.getsize(filepath)
            
            size_ratio = actual_size / expected_size
            
            if size_ratio > 1.2:  # 20% larger than expected
                print(f"[?] File larger than expected: {size_ratio:.2f}x")
                suspicious_metadata.append(f"Size anomaly: {size_ratio:.2f}x expected size")
            
            if suspicious_metadata:
                print(f"[!] Suspicious metadata found:")
                for item in suspicious_metadata:
                    print(f"    - {item}")
                return {'metadata': suspicious_metadata}
                
        except Exception as e:
            print(f"[-] Error checking metadata: {e}")
        
        return None
    
    def generate_report(self):
        """Generate a report of the analysis results."""
        if not self.results:
            print("\n[i] No hidden messages detected.")
            return
        
        print("\n" + "="*60)
        print("STEGANOGRAPHY ANALYSIS REPORT")
        print("="*60)
        
        for i, result in enumerate(self.results, 1):
            print(f"\n[{i}] File: {result['file']}")
            print(f"    Method: {result['method']}")
            print(f"    Details: {result['result']}")
        
        print(f"\n[!] Total suspicious files: {len(self.results)}")
        print("[!] Manual verification recommended for all detections.")

def main():
    parser = argparse.ArgumentParser(description='Steganography Brute Force Tool')
    parser.add_argument('file', help='Image file to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize tool
    stego_tool = StegoBruteForcer()
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