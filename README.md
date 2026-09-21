# StegoVault — Full Stack Image Steganography

## Features
- Frontend: HTML + CSS + JavaScript
- Backend: Python Flask REST API
- Password-protected AES-GCM encryption
- Scrypt password-based key derivation
- PNG LSB steganography
- Capacity checker
- Text ↔ Binary converter
- Optional 3× bit repetition (educational resilience mode)
- Responsive, user-friendly UI

## Important WhatsApp limitation
Normal LSB steganography is designed for lossless PNG pixels. WhatsApp and similar services may recompress/resize images, changing pixel values. Therefore this project does NOT claim guaranteed WhatsApp resistance.

For a demonstration, send the encoded PNG as a Document/File rather than as a normal compressed photo. The "3× repetition" mode is only an educational redundancy feature and is not a guarantee against recompression.

## Run locally
1. Install Python 3.11+.
2. Open terminal in this folder.
3. Create a virtual environment:
   python -m venv venv
4. Activate:
   Windows: venv\Scripts\activate
5. Install:
   pip install -r requirements.txt
6. Run:
   python app.py
7. Open:
   http://127.0.0.1:5000

## Project architecture
Browser → Flask API → AES-GCM/Scrypt → LSB encoder → PNG
Browser → Flask API → LSB decoder → AES-GCM decrypt → message
