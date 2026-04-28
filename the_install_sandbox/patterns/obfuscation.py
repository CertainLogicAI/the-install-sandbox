"""Obfuscation and encoding detection."""

OBFUSCATION_PATTERNS = [
    # Base64
    r"['\"`][A-Za-z0-9+/]{40,}={0,2}['\"`]",
    # Hex encoding
    r"['\"`][0-9a-fA-F]{40,}['\"`]",
    # URL encoding
    r"%[0-9a-fA-F]{2}",
    # chr/obfuscation
    r"chr\s*\(\s*\d+\s*\)",
    r"chr\s*\(\s*0x[0-9a-fA-F]+\s*\)",
    # String concatenation obfuscation
    r"['\"`][a-zA-Z0-9]{1,3}['\"`]\s*\+\s*['\"`][a-zA-Z0-9]{1,3}['\"`]",
    # exec with encoded payload
    r"exec\s*\(\s*(base64|binascii|codecs)\.",
]

SUSPICIOUS_STRING_OPS = [
    "base64.b64decode",
    "binascii.unhexlify",
    "codecs.decode",
    "zlib.decompress",
    "marshal.loads",
    "pickle.loads",
]
