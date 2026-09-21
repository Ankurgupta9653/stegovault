from flask import Flask, render_template, request, send_file, jsonify
from PIL import Image
from io import BytesIO
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB


MAGIC = b"STGV1"
SALT_LEN = 16
NONCE_LEN = 12


# -----------------------------
# Password Key Generation
# -----------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32
    )


# -----------------------------
# Encrypt Message
# -----------------------------

def encrypt_message(message: str, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    key = derive_key(password, salt)
    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return MAGIC + salt + nonce + ciphertext


# -----------------------------
# Decrypt Message
# -----------------------------

def decrypt_message(payload: bytes, password: str) -> str:

    min_len = len(MAGIC) + SALT_LEN + NONCE_LEN + 16

    if len(payload) < min_len:
        raise ValueError("No valid StegoVault message found.")

    if payload[:len(MAGIC)] != MAGIC:
        raise ValueError("No valid StegoVault message found.")

    pos = len(MAGIC)

    salt = payload[pos:pos + SALT_LEN]
    pos += SALT_LEN

    nonce = payload[pos:pos + NONCE_LEN]
    pos += NONCE_LEN

    ciphertext = payload[pos:]

    key = derive_key(password, salt)
    aes = AESGCM(key)

    try:
        plain = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError(
            "Wrong password or damaged/modified image."
        )

    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid hidden message.")


# -----------------------------
# Bytes → Bits
# -----------------------------

def bytes_to_bits(data: bytes):

    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


# -----------------------------
# Bits → Bytes
# -----------------------------

def bits_to_bytes(bits):

    out = bytearray()
    value = 0
    count = 0

    for bit in bits:

        value = (value << 1) | bit
        count += 1

        if count == 8:
            out.append(value)
            value = 0
            count = 0

    return bytes(out)


# -----------------------------
# Encode using LSB
# -----------------------------

def encode_lsb(
    img: Image.Image,
    payload: bytes,
    repeat: int = 1
) -> Image.Image:

    img = img.convert("RGB")

    raw = bytearray(img.tobytes())

    bits = list(bytes_to_bits(payload))

    repeated = []

    for bit in bits:
        repeated.extend([bit] * repeat)

    if len(repeated) > len(raw):
        raise ValueError(
            "Payload too large for this image. Use a larger PNG."
        )

    for i, bit in enumerate(repeated):
        raw[i] = (raw[i] & 0xFE) | bit

    out = Image.frombytes(
        "RGB",
        img.size,
        bytes(raw)
    )

    return out


# -----------------------------
# Decode using LSB
# -----------------------------

def decode_lsb(
    img: Image.Image,
    max_bytes=4_000_000,
    repeat=1
) -> bytes:

    img = img.convert("RGB")

    raw = img.tobytes()

    bits = [(byte & 1) for byte in raw]

    if repeat > 1:

        useful = []

        for i in range(0, len(bits), repeat):

            group = bits[i:i + repeat]

            if len(group) < repeat:
                break

            useful.append(
                1 if sum(group) > repeat / 2 else 0
            )

        bits = useful

    data = bits_to_bytes(bits)

    if len(data) > max_bytes:
        data = data[:max_bytes]

    return data


# -----------------------------
# Home Page
# -----------------------------

@app.route("/")
def index():
    return render_template("index.html")


# -----------------------------
# Encode API
# -----------------------------

@app.post("/api/encode")
def encode():

    image_file = request.files.get("image")
    message = request.form.get("message", "")
    password = request.form.get("password", "")
    resilience = request.form.get("resilience", "normal")

    if not image_file or not message or not password:
        return jsonify(
            error="Image, secret message and password are required."
        ), 400

    try:

        img = Image.open(image_file)

        if img.format != "PNG":
            return jsonify(
                error="Please upload a PNG image for reliable LSB encoding."
            ), 400

        # IMPORTANT:
        # Encrypt message BEFORE hiding it inside image.
        payload = encrypt_message(
            message,
            password
        )

        repeat = 3 if resilience == "repeat3" else 1

        result = encode_lsb(
            img,
            payload,
            repeat=repeat
        )

        buf = BytesIO()

        result.save(
            buf,
            format="PNG"
        )

        buf.seek(0)

        return send_file(
            buf,
            mimetype="image/png",
            as_attachment=True,
            download_name="stegovault_encoded.png"
        )

    except Exception as e:

        return jsonify(
            error=str(e)
        ), 400


# -----------------------------
# Decode API
# -----------------------------

@app.post("/api/decode")
def decode():

    image_file = request.files.get("image")
    password = request.form.get("password", "")
    resilience = request.form.get("resilience", "normal")

    if not image_file or not password:
        return jsonify(
            error="PNG image and password are required."
        ), 400

    try:

        img = Image.open(image_file)

        if img.format != "PNG":
            return jsonify(
                error="Use the original PNG encoded by StegoVault."
            ), 400

        repeat = 3 if resilience == "repeat3" else 1

        payload = decode_lsb(
            img,
            repeat=repeat
        )

        message = decrypt_message(
            payload,
            password
        )

        return jsonify(
            message=message
        )

    except Exception as e:

        return jsonify(
            error=str(e)
        ), 400


# -----------------------------
# Binary Conversion API
# -----------------------------

@app.post("/api/binary")
def binary():

    mode = request.form.get(
        "mode",
        "text_to_binary"
    )

    value = request.form.get(
        "value",
        ""
    )

    try:

        if mode == "text_to_binary":

            result = "".join(
                f"{byte:08b}"
                for byte in value.encode("utf-8")
            )

        elif mode == "binary_to_text":

            clean = "".join(
                value.split()
            )

            if (
                not clean
                or any(c not in "01" for c in clean)
                or len(clean) % 8 != 0
            ):
                raise ValueError(
                    "Enter valid binary in groups of 8 bits."
                )

            data = bytes(
                int(clean[i:i + 8], 2)
                for i in range(0, len(clean), 8)
            )

            result = data.decode("utf-8")

        else:

            raise ValueError(
                "Invalid conversion mode."
            )

        return jsonify(
            result=result
        )

    except Exception as e:

        return jsonify(
            error=str(e)
        ), 400


# -----------------------------
# Image Capacity API
# -----------------------------

@app.post("/api/capacity")
def capacity():

    image_file = request.files.get("image")

    if not image_file:
        return jsonify(
            error="PNG image required."
        ), 400

    try:

        img = Image.open(
            image_file
        ).convert("RGB")

        capacity_bytes = (
            img.width * img.height * 3
        ) // 8

        return jsonify(
            width=img.width,
            height=img.height,
            capacity_bytes=capacity_bytes,
            capacity_kb=round(
                capacity_bytes / 1024,
                2
            )
        )

    except Exception as e:

        return jsonify(
            error=str(e)
        ), 400


# -----------------------------
# Start Flask Server
# -----------------------------

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )