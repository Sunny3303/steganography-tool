import tkinter as tk
from tkinter import filedialog, messagebox
import wave
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import cv2
import os

# === CRYPTO UTILS ===
def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

def derive_key(password):
    return sha256(password.encode()).digest()

def encrypt_data(data, password):
    key = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data))

def decrypt_data(ciphertext, password):
    key = derive_key(password)
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[16:]))

def bytes_to_bits(data):
    return [int(bit) for byte in data for bit in f"{byte:08b}"]

def bits_to_bytes(bits):
    return bytes(int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8))

# === MARKERS ===
MAGIC_IMG = b'STEGI'
MAGIC_VID = b'STEGV'
MAGIC_AUD = b'STEGA'

# === IMAGE FUNCTIONS ===
def hide_data_in_image(image_path, secret_file_path, output_image_path, password):
    with open(secret_file_path, 'rb') as f:
        data = f.read()
    encrypted = encrypt_data(MAGIC_IMG + data, password)
    bits = bytes_to_bits(encrypted)

    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat_pixels = pixels.flatten().copy()

    if len(bits) > len(flat_pixels):
        raise ValueError("Data too large for image.")

    for i, bit in enumerate(bits):
        flat_pixels[i] = (flat_pixels[i] & 0b11111110) | bit

    new_pixels = flat_pixels.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels.astype(np.uint8))
    new_img.save(output_image_path)

def extract_data_from_image(image_path, password):
    img = Image.open(image_path).convert("RGB")
    bits = [val & 1 for val in np.array(img).flatten()]
    data = bits_to_bytes(bits)
    decrypted = decrypt_data(data, password)
    if not decrypted.startswith(MAGIC_IMG):
        raise ValueError("Invalid password or no data found.")
    return decrypted[len(MAGIC_IMG):]

# === VIDEO FUNCTIONS ===
def hide_data_in_video(video_path, secret_file_path, output_video_path, password):
    with open(secret_file_path, 'rb') as f:
        data = f.read()
    encrypted = encrypt_data(MAGIC_VID + data, password)
    bits = bytes_to_bits(encrypted)
    bit_index = 0

    cap = cv2.VideoCapture(video_path)
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    fps = cap.get(cv2.CAP_PROP_FPS)
    size = (int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)))
    out = cv2.VideoWriter(output_video_path, fourcc, fps, size)

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        flat_frame = frame.flatten()
        for i in range(len(flat_frame)):
            if bit_index >= len(bits):
                break
            flat_frame[i] = (flat_frame[i] & ~1) | bits[bit_index]
            bit_index += 1

        new_frame = flat_frame.reshape(frame.shape)
        out.write(new_frame.astype(np.uint8))

    cap.release()
    out.release()

def extract_data_from_video(video_path, password):
    cap = cv2.VideoCapture(video_path)
    bits = []
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        bits.extend([val & 1 for val in frame.flatten()])
    cap.release()

    data = bits_to_bytes(bits)
    decrypted = decrypt_data(data, password)
    if not decrypted.startswith(MAGIC_VID):
        raise ValueError("Invalid password or no data found.")
    return decrypted[len(MAGIC_VID):]

# === AUDIO FUNCTIONS ===
def hide_data_in_audio(audio_path, secret_file_path, output_audio_path, password):
    with open(secret_file_path, 'rb') as f:
        data = f.read()
    encrypted = encrypt_data(MAGIC_AUD + data, password)
    bits = bytes_to_bits(encrypted)

    with wave.open(audio_path, 'rb') as wav_in:
        params = wav_in.getparams()
        frames = np.frombuffer(wav_in.readframes(params.nframes), dtype=np.int16)

    if len(bits) > len(frames):
        raise ValueError("Data too large for audio file.")

    for i, bit in enumerate(bits):
        frames[i] = (frames[i] & ~1) | bit

    with wave.open(output_audio_path, 'wb') as wav_out:
        wav_out.setparams(params)
        wav_out.writeframes(frames.tobytes())

def extract_data_from_audio(audio_path, password):
    with wave.open(audio_path, 'rb') as wav:
        frames = np.frombuffer(wav.readframes(wav.getnframes()), dtype=np.int16)

    bits = [sample & 1 for sample in frames]
    data = bits_to_bytes(bits)
    decrypted = decrypt_data(data, password)
    if not decrypted.startswith(MAGIC_AUD):
        raise ValueError("Invalid password or no data found.")
    return decrypted[len(MAGIC_AUD):]

# === GUI FUNCTIONS ===
def browse_file(entry_widget):
    path = filedialog.askopenfilename()
    if path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)

def browse_save(entry_widget):
    path = filedialog.asksaveasfilename()
    if path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)

def handle_action(action_mode):
    try:
        media_type = media_type_var.get()
        secret_file_path = secret_file_entry.get()
        media_file_path = media_file_entry.get()
        output_file_path = output_file_entry.get()
        password = password_entry.get()

        if action_mode == "hide":
            if media_type == "Image":
                hide_data_in_image(media_file_path, secret_file_path, output_file_path, password)
            elif media_type == "Video":
                hide_data_in_video(media_file_path, secret_file_path, output_file_path, password)
            elif media_type == "Audio":
                hide_data_in_audio(media_file_path, secret_file_path, output_file_path, password)
            messagebox.showinfo("Success", f"✅ Data hidden successfully in {output_file_path}")

        elif action_mode == "extract":
            if media_type == "Image":
                extracted_data = extract_data_from_image(media_file_path, password)
            elif media_type == "Video":
                extracted_data = extract_data_from_video(media_file_path, password)
            elif media_type == "Audio":
                extracted_data = extract_data_from_audio(media_file_path, password)
            with open(output_file_path, "wb") as f:
                f.write(extracted_data)
            messagebox.showinfo("Success", f"✅ Data extracted to {output_file_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# === TKINTER SETUP ===
root = tk.Tk()
root.title("🔐 Steganography GUI Tool")
root.geometry("500x400")

media_type_var = tk.StringVar(value="Image")

# Media Type
tk.Label(root, text="Media Type:").pack()
tk.OptionMenu(root, media_type_var, "Image", "Video", "Audio").pack()

# Media File
tk.Label(root, text="Media File (Image/Video/Audio):").pack()
media_file_entry = tk.Entry(root, width=50)
media_file_entry.pack()
tk.Button(root, text="Browse", command=lambda: browse_file(media_file_entry)).pack()

# Secret File (for hiding)
tk.Label(root, text="Secret File to Hide (Only for Hiding):").pack()
secret_file_entry = tk.Entry(root, width=50)
secret_file_entry.pack()
tk.Button(root, text="Browse", command=lambda: browse_file(secret_file_entry)).pack()

# Output File
tk.Label(root, text="Output File Path:").pack()
output_file_entry = tk.Entry(root, width=50)
output_file_entry.pack()
tk.Button(root, text="Save As", command=lambda: browse_save(output_file_entry)).pack()

# Password
tk.Label(root, text="Password:").pack()
password_entry = tk.Entry(root, show="*", width=50)
password_entry.pack()

# Buttons
tk.Button(root, text="Hide Data", bg="lightgreen", command=lambda: handle_action("hide")).pack(pady=10)
tk.Button(root, text="Extract Data", bg="lightblue", command=lambda: handle_action("extract")).pack(pady=5)

root.mainloop()
