from PIL import Image
import hashlib, io

def normalize_and_hash(file_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    normalized = buffer.getvalue()
    return hashlib.sha256(normalized).hexdigest()

def simulate_resave(file_bytes: bytes) -> bytes:
    img = Image.open(io.BytesIO(file_bytes))
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

def simulate_jpeg_conversion(file_bytes: bytes) -> bytes:
    img = Image.open(io.BytesIO(file_bytes))
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG", quality=95)
    buffer.seek(0)
    img2 = Image.open(buffer)
    buffer2 = io.BytesIO()
    img2.save(buffer2, format="PNG")
    return buffer2.getvalue()

def simulate_screenshot(file_bytes: bytes) -> bytes:
    img = Image.open(io.BytesIO(file_bytes))
    img = img.resize(img.size, Image.LANCZOS)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

with open(r"C:\Users\anush\OneDrive\Pictures\IMG_0051.PNG", "rb") as f:
    original_bytes = f.read()

original_hash      = normalize_and_hash(original_bytes)
resaved_hash       = normalize_and_hash(simulate_resave(original_bytes))
screenshot_hash    = normalize_and_hash(simulate_screenshot(original_bytes))

print("=== Normalization Test ===")
print(f"Original hash:   {original_hash}")
print(f"Resaved hash:    {resaved_hash}")
print(f"Screenshot hash: {screenshot_hash}")
print()

if original_hash == resaved_hash == screenshot_hash:
    print("PASS — all three produce identical hashes after normalization")
else:
    print("RESULTS:")
    print(f"  Original == Resaved:    {original_hash == resaved_hash}")
    print(f"  Original == Screenshot: {original_hash == screenshot_hash}")