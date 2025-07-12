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
def hide_data_in_image(input_image, secret_file, output_image, password):
    with open(secret_file, 'rb') as f:
        data = f.read()
    encrypted = encrypt_data(MAGIC_IMG + data, password)
    bits = bytes_to_bits(encrypted)

    img = Image.open(input_image).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.flatten().copy()

    if len(bits) > len(flat):
        raise ValueError("Data too large for image.")

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0b11111110) | bit

    new_pixels = flat.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels.astype(np.uint8))
    new_img.save(output_image)

def extract_data_from_image(image_path, password):
    img = Image.open(image_path).convert("RGB")
    bits = [val & 1 for val in np.array(img).flatten()]
    data = bits_to_bytes(bits)
    decrypted = decrypt_data(data, password)
    if not decrypted.startswith(MAGIC_IMG):
        raise ValueError("Invalid password or no data found.")
    return decrypted[len(MAGIC_IMG):]

# === VIDEO FUNCTIONS ===
def hide_data_in_video(input_video, secret_file, output_video, password):
    with open(secret_file, 'rb') as f:
        data = f.read()
    encrypted = encrypt_data(MAGIC_VID + data, password)
    bits = bytes_to_bits(encrypted)
    bit_index = 0

    cap = cv2.VideoCapture(input_video)
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    fps = cap.get(cv2.CAP_PROP_FPS)
    size = (int(cap.get(3)), int(cap.get(4)))
    out = cv2.VideoWriter(output_video, fourcc, fps, size)

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret: break

        flat = frame.flatten()
        for i in range(len(flat)):
            if bit_index >= len(bits): break
            flat[i] = (flat[i] & ~1) | bits[bit_index]
            bit_index += 1

        out.write(flat.reshape(frame.shape).astype(np.uint8))

    cap.release()
    out.release()

def extract_data_from_video(video_path, password):
    cap = cv2.VideoCapture(video_path)
    bits = []
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret: break
        bits.extend([val & 1 for val in frame.flatten()])
    cap.release()

    data = bits_to_bytes(bits)
    decrypted = decrypt_data(data, password)
    if not decrypted.startswith(MAGIC_VID):
        raise ValueError("Invalid password or no data found.")
    return decrypted[len(MAGIC_VID):]

# === AUDIO FUNCTIONS ===
def hide_data_in_audio(input_audio, secret_file, output_audio, password):
    with open(secret_file, 'rb') as f:
        data = f.read()
    encrypted = encrypt_data(MAGIC_AUD + data, password)
    bits = bytes_to_bits(encrypted)

    with wave.open(input_audio, 'rb') as wav_in:
        params = wav_in.getparams()
        frames = np.frombuffer(wav_in.readframes(params.nframes), dtype=np.int16)

    if len(bits) > len(frames):
        raise ValueError("Data too large for audio file.")

    for i, bit in enumerate(bits):
        frames[i] = (frames[i] & ~1) | bit

    with wave.open(output_audio, 'wb') as wav_out:
        wav_out.setparams(params)
        wav_out.writeframes(frames.tobytes())

def extract_data_from_audio(audio_path, password):
    with wave.open(audio_path, 'rb') as wav:
        frames = np.frombuffer(wav.readframes(wav.getnframes()), dtype=np.int16)

    bits = [s & 1 for s in frames]
    data = bits_to_bytes(bits)
    decrypted = decrypt_data(data, password)
    if not decrypted.startswith(MAGIC_AUD):
        raise ValueError("Invalid password or no data found.")
    return decrypted[len(MAGIC_AUD):]

# === GUI ===
def browse_file(entry):
    path = filedialog.askopenfilename()
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)

def browse_save(entry):
    path = filedialog.asksaveasfilename()
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)

def browse_folder(entry):
    path = filedialog.askdirectory()
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)

def handle_action(mode):
    try:
        media_type = var_media.get()
        file_path = entry_file.get()
        media_path = entry_media.get()
        output_path = entry_output.get()
        password = entry_password.get()

        if mode == "hide":
            if media_type == "Image":
                hide_data_in_image(media_path, file_path, output_path, password)
            elif media_type == "Video":
                hide_data_in_video(media_path, file_path, output_path, password)
            elif media_type == "Audio":
                hide_data_in_audio(media_path, file_path, output_path, password)
            messagebox.showinfo("Success", f"✅ Data hidden successfully in {output_path}")

        elif mode == "extract":
            if media_type == "Image":
                data = extract_data_from_image(media_path, password)
            elif media_type == "Video":
                data = extract_data_from_video(media_path, password)
            elif media_type == "Audio":
                data = extract_data_from_audio(media_path, password)
            with open(output_path, "wb") as f:
                f.write(data)
            messagebox.showinfo("Success", f"✅ Data extracted to {output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Tkinter setup
root = tk.Tk()
root.title("🔐 Steganography GUI Tool")
root.geometry("500x400")

var_media = tk.StringVar(value="Image")

# Media Type
tk.Label(root, text="Media Type:").pack()
tk.OptionMenu(root, var_media, "Image", "Video", "Audio").pack()

# Media File
tk.Label(root, text="Media File (Image/Video/Audio):").pack()
entry_media = tk.Entry(root, width=50)
entry_media.pack()
tk.Button(root, text="Browse", command=lambda: browse_file(entry_media)).pack()

# Secret File (for hiding)
tk.Label(root, text="Secret File to Hide (Only for Hiding):").pack()
entry_file = tk.Entry(root, width=50)
entry_file.pack()
tk.Button(root, text="Browse", command=lambda: browse_file(entry_file)).pack()

# Output File
tk.Label(root, text="Output File Path:").pack()
entry_output = tk.Entry(root, width=50)
entry_output.pack()
tk.Button(root, text="Save As", command=lambda: browse_save(entry_output)).pack()

# Password
tk.Label(root, text="Password:").pack()
entry_password = tk.Entry(root, show="*", width=50)
entry_password.pack()

tk.Button(root, text="Hide Data", bg="lightgreen", command=lambda: handle_action("hide")).pack(pady=10)
tk.Button(root, text="Extract Data", bg="lightblue", command=lambda: handle_action("extract")).pack(pady=5)

# Run the app
root.mainloop()