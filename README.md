# Forensic File Analyzer 

## Overview
Forensic File Analyzer Pro is a Python-based desktop application designed for digital forensic analysis of files. It provides detailed information about a file's basic properties, metadata, cryptographic hashes, file type, and a timeline visualization of file events (created, modified, accessed). The application also supports file comparison and report generation in JSON or CSV formats.

## Features
- **Basic File Information**: Displays file name, path, size, creation/modification/access times, and platform details.
- **Metadata Extraction**: Extracts metadata from supported file types (JPG, PDF, DOCX).
- **Hash Calculation**: Computes MD5, SHA1, SHA256, and SHA512 hashes for file integrity verification.
- **File Type Detection**: Identifies file types using `python-magic` or `mimetypes` if `python-magic` is unavailable.
- **Timeline Visualization**: Visualizes file creation, modification, and access times using a Matplotlib-based timeline.
- **File Comparison**: Compares two files based on size, SHA256 hash, and file extension.
- **Report Export**: Exports analysis results to JSON or CSV formats.
- **Modern UI**: Built with `tkinter` and `ttkthemes` for a modern, dark-themed interface.

## Requirements
- Python 3.6+
- Required Python packages:
  - `tkinter` (usually included with Python)
  - `ttkthemes`
  - `exifread`
  - `PyPDF2`
  - `python-docx`
  - `matplotlib`
  - `python-magic` (optional, for enhanced file type detection)
- Install dependencies using:
  ```bash
  pip install ttkthemes exifread PyPDF2 python-docx matplotlib python-magic
  ```

## Installation
1. Clone the repository:
   ```bash
   git clone 
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python forensic_analyzer.py
   ```

## Usage
1. Launch the application by running the script.
2. Click "Select File" to choose a file for analysis.
3. Optionally, click "Select Comparison File" to compare two files.
4. View analysis results in the tabs:
   - **Basic Info**: File properties like name, size, and timestamps.
   - **Metadata**: File-specific metadata (e.g., EXIF for images, document properties for DOCX).
   - **Hash**: Cryptographic hashes (MD5, SHA1, SHA256, SHA512).
   - **File Type**: Detected file type.
   - **Timeline**: Visual representation of file event timestamps.
   - **Comparison**: Results of file comparison (if applicable).
5. Click "Export Report" to save the analysis as a JSON or CSV file.

## Notes
- The application uses threading to prevent UI freezing during file processing.
- If `python-magic` is not installed, the application falls back to `mimetypes` for file type detection.
- Supported file types for metadata extraction include JPG/JPEG, PDF, and DOCX. Other file types will show limited metadata.
- The timeline visualization uses Matplotlib and is displayed within the application window.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author
Nugra