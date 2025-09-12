#!/usr/bin/env python3
"""
Certificate Scanner CLI
Scans filesystem for SSL/TLS certificates and stores information in SQLite database.
"""

import os
import sys
import sqlite3
import argparse
import logging
import mimetypes
from pathlib import Path
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID
import concurrent.futures
import threading

# Thread-local storage for database connections
thread_local = threading.local()

class CertificateScanner:
    def __init__(self, db_path="certificates.db", max_workers=4):
        self.db_path = db_path
        self.max_workers = max_workers
        self.setup_logging()
        self.setup_database()
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cert_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def get_db_connection(self):
        """Get thread-local database connection"""
        if not hasattr(thread_local, 'connection'):
            thread_local.connection = sqlite3.connect(self.db_path)
            thread_local.connection.row_factory = sqlite3.Row
        return thread_local.connection
        
    def setup_database(self):
        """Initialize SQLite database with certificates table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                file_modified TIMESTAMP,
                cert_format TEXT,
                subject_common_name TEXT,
                subject_organization TEXT,
                subject_organizational_unit TEXT,
                subject_country TEXT,
                subject_state TEXT,
                subject_locality TEXT,
                subject_email TEXT,
                issuer_common_name TEXT,
                issuer_organization TEXT,
                issuer_organizational_unit TEXT,
                issuer_country TEXT,
                issuer_state TEXT,
                issuer_locality TEXT,
                serial_number TEXT,
                version INTEGER,
                signature_algorithm TEXT,
                public_key_algorithm TEXT,
                public_key_size INTEGER,
                not_before TIMESTAMP,
                not_after TIMESTAMP,
                is_expired BOOLEAN,
                days_until_expiry INTEGER,
                fingerprint_sha1 TEXT,
                fingerprint_sha256 TEXT,
                subject_alt_names TEXT,
                key_usage TEXT,
                extended_key_usage TEXT,
                is_ca BOOLEAN,
                is_self_signed BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(file_path, fingerprint_sha256)
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON certificates(file_path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_expiry ON certificates(not_after)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint ON certificates(fingerprint_sha256)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subject_cn ON certificates(subject_common_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_issuer_cn ON certificates(issuer_common_name)")
        
        conn.commit()
        conn.close()
        
    def extract_name_attribute(self, name, oid):
        """Extract attribute from X.509 Name object"""
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, AttributeError):
            return None
            
    def parse_certificate_data(self, cert):
        """Extract detailed information from certificate"""
        data = {}
        
        # Subject information
        subject = cert.subject
        data['subject_common_name'] = self.extract_name_attribute(subject, NameOID.COMMON_NAME)
        data['subject_organization'] = self.extract_name_attribute(subject, NameOID.ORGANIZATION_NAME)
        data['subject_organizational_unit'] = self.extract_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
        data['subject_country'] = self.extract_name_attribute(subject, NameOID.COUNTRY_NAME)
        data['subject_state'] = self.extract_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME)
        data['subject_locality'] = self.extract_name_attribute(subject, NameOID.LOCALITY_NAME)
        data['subject_email'] = self.extract_name_attribute(subject, NameOID.EMAIL_ADDRESS)
        
        # Issuer information
        issuer = cert.issuer
        data['issuer_common_name'] = self.extract_name_attribute(issuer, NameOID.COMMON_NAME)
        data['issuer_organization'] = self.extract_name_attribute(issuer, NameOID.ORGANIZATION_NAME)
        data['issuer_organizational_unit'] = self.extract_name_attribute(issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)
        data['issuer_country'] = self.extract_name_attribute(issuer, NameOID.COUNTRY_NAME)
        data['issuer_state'] = self.extract_name_attribute(issuer, NameOID.STATE_OR_PROVINCE_NAME)
        data['issuer_locality'] = self.extract_name_attribute(issuer, NameOID.LOCALITY_NAME)
        
        # Basic certificate information
        data['serial_number'] = str(cert.serial_number)
        data['version'] = cert.version.value
        data['signature_algorithm'] = cert.signature_algorithm_oid._name
        
        # Public key information
        public_key = cert.public_key()
        data['public_key_algorithm'] = public_key.__class__.__name__.replace('PublicKey', '').replace('_', ' ')
        
        try:
            data['public_key_size'] = public_key.key_size
        except AttributeError:
            data['public_key_size'] = None
            
        # Validity period
        data['not_before'] = cert.not_valid_before
        data['not_after'] = cert.not_valid_after
        
        now = datetime.now()
        data['is_expired'] = cert.not_valid_after < now
        data['days_until_expiry'] = (cert.not_valid_after - now).days
        
        # Fingerprints
        data['fingerprint_sha1'] = cert.fingerprint(hashes.SHA1()).hex().upper()
        data['fingerprint_sha256'] = cert.fingerprint(hashes.SHA256()).hex().upper()
        
        # Extensions
        data['subject_alt_names'] = self.extract_san(cert)
        data['key_usage'] = self.extract_key_usage(cert)
        data['extended_key_usage'] = self.extract_extended_key_usage(cert)
        data['is_ca'] = self.is_ca_certificate(cert)
        data['is_self_signed'] = cert.issuer == cert.subject
        
        return data
        
    def extract_san(self, cert):
        """Extract Subject Alternative Names"""
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return ', '.join([name.value for name in san_ext.value])
        except x509.ExtensionNotFound:
            return None
            
    def extract_key_usage(self, cert):
        """Extract Key Usage extension"""
        try:
            ku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            usages = []
            if ku_ext.value.digital_signature: usages.append('digital_signature')
            if ku_ext.value.key_encipherment: usages.append('key_encipherment')
            if ku_ext.value.key_agreement: usages.append('key_agreement')
            if ku_ext.value.key_cert_sign: usages.append('key_cert_sign')
            if ku_ext.value.crl_sign: usages.append('crl_sign')
            if ku_ext.value.content_commitment: usages.append('content_commitment')
            if ku_ext.value.data_encipherment: usages.append('data_encipherment')
            return ', '.join(usages)
        except x509.ExtensionNotFound:
            return None
            
    def extract_extended_key_usage(self, cert):
        """Extract Extended Key Usage extension"""
        try:
            eku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            return ', '.join([usage._name for usage in eku_ext.value])
        except x509.ExtensionNotFound:
            return None
            
    def is_ca_certificate(self, cert):
        """Check if certificate is a CA certificate"""
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
            return basic_constraints.value.ca
        except x509.ExtensionNotFound:
            return False
            
    def load_certificate_from_data(self, data, file_format):
        """Load certificate from binary data"""
        certificates = []
        
        try:
            if file_format == 'PEM':
                # Handle multiple PEM certificates in one file
                cert_data = data.decode('utf-8', errors='ignore')
                pem_blocks = []
                current_block = []
                in_cert = False
                
                for line in cert_data.split('\n'):
                    if '-----BEGIN CERTIFICATE-----' in line:
                        in_cert = True
                        current_block = [line]
                    elif '-----END CERTIFICATE-----' in line and in_cert:
                        current_block.append(line)
                        pem_blocks.append('\n'.join(current_block))
                        current_block = []
                        in_cert = False
                    elif in_cert:
                        current_block.append(line)
                        
                for pem_block in pem_blocks:
                    try:
                        cert = x509.load_pem_x509_certificate(pem_block.encode())
                        certificates.append(cert)
                    except Exception as e:
                        self.logger.debug(f"Failed to parse PEM block: {e}")
                        
            elif file_format == 'DER':
                cert = x509.load_der_x509_certificate(data)
                certificates.append(cert)
                
            elif file_format == 'PKCS12':
                try:
                    # Try with empty password first
                    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(data, None)
                    if cert:
                        certificates.append(cert)
                    if additional_certs:
                        certificates.extend(additional_certs)
                except Exception:
                    # Try with common passwords
                    common_passwords = [b'', b'password', b'changeit', b'123456']
                    for password in common_passwords:
                        try:
                            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(data, password)
                            if cert:
                                certificates.append(cert)
                            if additional_certs:
                                certificates.extend(additional_certs)
                            break
                        except Exception:
                            continue
                            
        except Exception as e:
            self.logger.debug(f"Failed to load certificate: {e}")
            
        return certificates
        
    def detect_certificate_format(self, file_path, data):
        """Detect certificate format based on content and file extension"""
        # Check file extension first
        ext = file_path.suffix.lower()
        
        if ext in ['.pem', '.crt', '.cer', '.cert']:
            if b'-----BEGIN CERTIFICATE-----' in data:
                return 'PEM'
        elif ext in ['.der']:
            return 'DER'
        elif ext in ['.p12', '.pfx', '.pkcs12']:
            return 'PKCS12'
            
        # Content-based detection
        if b'-----BEGIN CERTIFICATE-----' in data:
            return 'PEM'
        elif data.startswith(b'\x30\x82'):  # DER certificate starts with SEQUENCE
            return 'DER'
        elif data.startswith(b'\x30\x82') and len(data) > 100:
            # Could be PKCS#12
            return 'PKCS12'
            
        return None
        
    def is_potential_certificate_file(self, file_path):
        """Check if file might contain certificates"""
        # File extensions that commonly contain certificates
        cert_extensions = {'.pem', '.crt', '.cer', '.cert', '.der', '.p12', '.pfx', '.pkcs12', 
                          '.csr', '.key', '.pub', '.ca-bundle', '.ca', '.pem.crt'}
        
        # Check extension
        if file_path.suffix.lower() in cert_extensions:
            return True
            
        # Check common certificate file names
        cert_names = {'cert', 'certificate', 'ca-cert', 'server', 'client', 'root', 'intermediate'}
        if any(name in file_path.name.lower() for name in cert_names):
            return True
            
        # macOS-specific: Check for keychain files and common macOS cert locations
        if sys.platform == 'darwin':
            # Skip binary keychain files but check for exported certificates
            if file_path.suffix.lower() in {'.keychain', '.keychain-db'}:
                return False
            # Common macOS certificate file patterns
            macos_patterns = {'keychain', 'security', 'ssl', 'tls'}
            if any(pattern in file_path.name.lower() for pattern in macos_patterns):
                return True
            
        return False
        
    def scan_file(self, file_path):
        """Scan a single file for certificates"""
        try:
            if not self.is_potential_certificate_file(file_path):
                return 0
                
            if not os.access(file_path, os.R_OK):
                return 0
                
            # Skip very large files
            file_size = file_path.stat().st_size
            if file_size > 50 * 1024 * 1024:  # 50MB
                return 0
                
            with open(file_path, 'rb') as f:
                data = f.read()
                
            cert_format = self.detect_certificate_format(file_path, data)
            if not cert_format:
                return 0
                
            certificates = self.load_certificate_from_data(data, cert_format)
            
            count = 0
            for cert in certificates:
                try:
                    cert_data = self.parse_certificate_data(cert)
                    cert_data['file_path'] = str(file_path)
                    cert_data['file_size'] = file_size
                    cert_data['file_modified'] = datetime.fromtimestamp(file_path.stat().st_mtime)
                    cert_data['cert_format'] = cert_format
                    
                    self.store_certificate(cert_data)
                    count += 1
                    
                except Exception as e:
                    self.logger.debug(f"Failed to process certificate in {file_path}: {e}")
                    
            return count
            
        except Exception as e:
            self.logger.debug(f"Error scanning {file_path}: {e}")
            return 0
            
    def store_certificate(self, cert_data):
        """Store certificate data in database"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        columns = list(cert_data.keys())
        placeholders = ', '.join(['?' for _ in columns])
        column_names = ', '.join(columns)
        
        query = f"""
            INSERT OR REPLACE INTO certificates ({column_names})
            VALUES ({placeholders})
        """
        
        cursor.execute(query, list(cert_data.values()))
        conn.commit()
        
    def scan_directory(self, directory, recursive=True):
        """Scan directory for certificates"""
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            self.logger.error(f"Directory does not exist: {directory}")
            return 0
            
        self.logger.info(f"Scanning directory: {directory}")
        
        # Collect all potential certificate files
        files_to_scan = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                # Skip certain directories (including macOS-specific ones)
                skip_dirs = ['__pycache__', 'node_modules', '.git', '.svn']
                if sys.platform == 'darwin':
                    skip_dirs.extend(['.Trashes', '.Spotlight-V100', '.fseventsd', 
                                    '.DocumentRevisions-V100', '.TemporaryItems'])
                
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in skip_dirs]
                
                for file in files:
                    file_path = Path(root) / file
                    if self.is_potential_certificate_file(file_path):
                        files_to_scan.append(file_path)
        else:
            for file_path in directory.iterdir():
                if file_path.is_file() and self.is_potential_certificate_file(file_path):
                    files_to_scan.append(file_path)
                    
        self.logger.info(f"Found {len(files_to_scan)} potential certificate files")
        
        # Scan files using thread pool
        total_certificates = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_file, file_path) for file_path in files_to_scan]
            
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                try:
                    count = future.result()
                    total_certificates += count
                    if i % 100 == 0:
                        self.logger.info(f"Processed {i}/{len(files_to_scan)} files, found {total_certificates} certificates")
                except Exception as e:
                    self.logger.error(f"Error processing file: {e}")
                    
        return total_certificates
        
    def get_statistics(self):
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total certificates
        cursor.execute("SELECT COUNT(*) FROM certificates")
        stats['total_certificates'] = cursor.fetchone()[0]
        
        # Expired certificates
        cursor.execute("SELECT COUNT(*) FROM certificates WHERE is_expired = 1")
        stats['expired_certificates'] = cursor.fetchone()[0]
        
        # Expiring soon (30 days)
        cursor.execute("SELECT COUNT(*) FROM certificates WHERE days_until_expiry <= 30 AND NOT is_expired")
        stats['expiring_soon'] = cursor.fetchone()[0]
        
        # CA certificates
        cursor.execute("SELECT COUNT(*) FROM certificates WHERE is_ca = 1")
        stats['ca_certificates'] = cursor.fetchone()[0]
        
        # Self-signed certificates
        cursor.execute("SELECT COUNT(*) FROM certificates WHERE is_self_signed = 1")
        stats['self_signed'] = cursor.fetchone()[0]
        
        # Most common issuers
        cursor.execute("""
            SELECT issuer_common_name, COUNT(*) as count 
            FROM certificates 
            WHERE issuer_common_name IS NOT NULL
            GROUP BY issuer_common_name 
            ORDER BY count DESC 
            LIMIT 5
        """)
        stats['top_issuers'] = cursor.fetchall()
        
        conn.close()
        return stats

def main():
    parser = argparse.ArgumentParser(description='Scan filesystem for SSL/TLS certificates')
    
    # Set default paths based on operating system
    if sys.platform == 'darwin':  # macOS
        default_paths = ['/usr/local/share/ca-certificates', '/Library/Keychains', 
                        '/System/Library/Keychains', '/Applications', '/etc/ssl']
    else:  # Linux and others
        default_paths = ['/']
        
    parser.add_argument('paths', nargs='*', default=default_paths, 
                       help=f'Paths to scan (default: {", ".join(default_paths)})')
    parser.add_argument('-d', '--database', default='certificates.db', help='SQLite database path')
    parser.add_argument('-r', '--recursive', action='store_true', default=True, help='Recursive scan')
    parser.add_argument('--no-recursive', action='store_false', dest='recursive', help='Non-recursive scan')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of worker threads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    scanner = CertificateScanner(db_path=args.database, max_workers=args.workers)
    
    if args.stats:
        stats = scanner.get_statistics()
        print("\nCertificate Database Statistics:")
        print(f"Total certificates: {stats['total_certificates']}")
        print(f"Expired certificates: {stats['expired_certificates']}")
        print(f"Expiring soon (30 days): {stats['expiring_soon']}")
        print(f"CA certificates: {stats['ca_certificates']}")
        print(f"Self-signed certificates: {stats['self_signed']}")
        print("\nTop 5 Certificate Issuers:")
        for issuer, count in stats['top_issuers']:
            print(f"  {issuer}: {count}")
        return
    
    # Warn about potential permission issues on macOS
    if sys.platform == 'darwin':
        print("Note: On macOS, some system directories may require administrator privileges.")
        print("Consider running with 'sudo' for complete system scan, or scan specific directories.")
        print("Keychain certificates are typically not accessible as files - use 'security' command instead.\n")
    
    total_certificates = 0
    for path in args.paths:
        path_obj = Path(path)
        if path_obj.is_file():
            count = scanner.scan_file(path_obj)
            total_certificates += count
        elif path_obj.is_dir():
            try:
                count = scanner.scan_directory(path_obj, recursive=args.recursive)
                total_certificates += count
            except PermissionError:
                scanner.logger.warning(f"Permission denied accessing: {path}")
            except Exception as e:
                scanner.logger.error(f"Error scanning {path}: {e}")
        else:
            scanner.logger.error(f"Path does not exist: {path}")
            
    scanner.logger.info(f"Scan complete. Found {total_certificates} certificates.")
    scanner.logger.info(f"Database saved to: {args.database}")

if __name__ == '__main__':
    main()
