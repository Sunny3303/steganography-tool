# steganography-tool
# 🔐 Multimedia Steganography Tool (Image, Video, Audio) with AES Encryption

This is a powerful and easy-to-use **steganography tool** that allows you to **hide and extract encrypted data** inside **images, videos, and audio files**. Built with **Python** and a **Tkinter GUI**, it supports AES-256 encryption to ensure your hidden data stays secure.

---

## ✨ Features

- 🔒 **AES-256 Encryption (CBC Mode)** for data protection
- 🖼️ **Image Steganography** (PNG, BMP)
- 🎞️ **Video Steganography** (AVI format)
- 🔊 **Audio Steganography** (WAV format)
- 🔐 **Password-Protected** hiding and extraction
- 🧩 Supports any file type: `.txt`, `.zip`, `.pdf`, etc.
- 🖥️ **User-friendly GUI** — no command-line needed!

---

## 📸 Screenshots

> *(Add screenshots of the GUI interface here if available)*

---

## 🛠️ How It Works

### 🔐 Hide Data
1. Launch the app: `python stegano_gui.py`
2. Select media type: Image / Video / Audio
3. Browse to your media file (e.g., `cover.png`)
4. Browse to the secret file you want to hide (e.g., `secret.txt`)
5. Choose an output filename (e.g., `stego_image.png`)
6. Enter a strong password
7. Click **"Hide Data"** ✅

### 🔓 Extract Data
1. Select the same media type
2. Load the stego file (e.g., `stego_image.png`)
3. Enter the password used to hide
4. Choose an output file (e.g., `extracted_secret.txt`)
5. Click **"Extract Data"** ✅

---

## 💻 Requirements

Install dependencies:

```bash
pip install pillow numpy opencv-python pycryptodome
