# Certificate Discovery Tool

A Python CLI tool for scanning filesystems to discover and analyze SSL/TLS certificates. The tool extracts detailed certificate information and stores it in a SQLite database for querying and analysis.

## Features

- **Multi-format Support**: Handles PEM, DER, and PKCS#12 certificate formats
- **Comprehensive Analysis**: Extracts detailed certificate metadata including:
  - Subject and issuer information
  - Validity periods and expiration status
  - Public key details and algorithms
  - Fingerprints (SHA-1 and SHA-256)
  - Subject Alternative Names (SAN)
  - Key usage and extended key usage
  - CA and self-signed certificate detection
- **Database Storage**: SQLite database with indexed fields for fast queries
- **Multi-threaded Scanning**: Configurable worker threads for efficient processing
- **Cross-platform**: Works on macOS, Linux, and other Unix-like systems
- **Smart File Detection**: Identifies potential certificate files by extension and content
- **Statistics and Reporting**: Built-in statistics and analysis features

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scan default system directories:
```bash
python find_cert.py
```

Scan specific directories:
```bash
python find_cert.py /path/to/scan /another/path
```

### Command Line Options

```bash
python find_cert.py [OPTIONS] [PATHS...]

Options:
  -d, --database PATH     SQLite database path (default: certificates.db)
  -r, --recursive         Recursive scan (default: True)
  --no-recursive          Non-recursive scan
  -w, --workers N         Number of worker threads (default: 4)
  -v, --verbose           Verbose logging
  --stats                 Show database statistics
  -h, --help              Show help message
```

### Examples

Scan a specific directory recursively:
```bash
python find_cert.py -r /etc/ssl
```

Scan with custom database and more workers:
```bash
python find_cert.py -d my_certs.db -w 8 /usr/local/share/ca-certificates
```

Show statistics from existing database:
```bash
python find_cert.py --stats
```

Verbose scanning with custom paths:
```bash
python find_cert.py -v /home/user/certificates /var/ssl
```

## Database Schema

The tool creates a SQLite database with the following certificate information:

- **File Information**: Path, size, modification time, format
- **Subject Details**: Common name, organization, country, state, locality, email
- **Issuer Details**: Common name, organization, country, state, locality
- **Certificate Properties**: Serial number, version, signature algorithm
- **Public Key**: Algorithm, key size
- **Validity**: Not before/after dates, expiration status, days until expiry
- **Fingerprints**: SHA-1 and SHA-256
- **Extensions**: Subject Alternative Names, key usage, extended key usage
- **Flags**: CA certificate, self-signed status

## Supported File Types

The tool automatically detects and processes:

- **PEM files**: `.pem`, `.crt`, `.cer`, `.cert`
- **DER files**: `.der`
- **PKCS#12 files**: `.p12`, `.pfx`, `.pkcs12`
- **Other formats**: Files with certificate-related names or content

## Platform-Specific Notes

### macOS
- Default scan paths include `/Library/Keychains`, `/System/Library/Keychains`
- Some system directories may require administrator privileges
- Keychain certificates are not accessible as files (use `security` command instead)
- Automatically skips system-specific directories like `.Trashes`, `.Spotlight-V100`

### Linux
- Default scan path is root directory (`/`)
- May require appropriate permissions for system directories

## Output and Logging

- **Console Output**: Progress updates and summary information
- **Log File**: Detailed logging saved to `cert_scanner.log`
- **Database**: All certificate data stored in SQLite database
- **Statistics**: Summary statistics including counts, expiration status, and top issuers

## Performance Considerations

- Uses multi-threading for parallel file processing
- Skips files larger than 50MB to avoid memory issues
- Creates database indexes for efficient querying
- Thread-local database connections for thread safety

## Requirements

- Python 3.6+
- cryptography >= 41.0.0

## License

This project is open source. Please check the license file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## Troubleshooting

### Permission Issues
On macOS and Linux, some system directories may require elevated privileges:
```bash
sudo python find_cert.py
```

### Large File Systems
For very large file systems, consider:
- Using more worker threads (`-w` option)
- Scanning specific directories instead of root
- Using non-recursive scanning for targeted searches

### Database Queries
The SQLite database can be queried directly for custom analysis:
```bash
sqlite3 certificates.db "SELECT * FROM certificates WHERE is_expired = 1;"
```
