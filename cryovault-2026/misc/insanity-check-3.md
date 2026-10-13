### Summary

The challenge ships no files and a description of only `.`. The flag is hidden in the Cryovault 2026 Discord server, in the "2. Flag Format" bullet of the #rules message. Its code span renders as the visible decoy `isfcr{..}`, but it is surrounded by four zero-width codepoints that encode the real flag, two bits per character. Reading the codepoints in order and grouping the bits into bytes recovers the flag.

### Steps

1. Open the Discord server and find the #rules message. The invite used for this challenge is `https://discord.gg/KFxeMCuhvw`. In the #rules message, the "2. Flag Format" bullet has a code span that looks like `isfcr{..}`. The hidden payload is in that span.

2. Map the zero-width codepoints to bits. Each character carries two bits:

   | Codepoint | Name | Bits |
   | --- | --- | --- |
   | U+200C | ZWNJ | `00` |
   | U+200D | ZWJ | `01` |
   | U+202C | POP DIRECTIONAL FORMATTING | `10` |
   | U+FEFF | ZWNBSP (BOM) | `11` |

   Every other character in the span is ignored.

3. Group the bits into bytes and decode. Four symbols make one byte. The payload is interleaved with `0x00` padding bytes, which are four ZWNJ symbols each, so the decoder drops every zero byte. The captured code span is in `work/artifacts/zw_rules_flag.txt`, and the decoder reads it by default:

   ```sh
   python3 work/scripts/decode_zw.py
   ```

   ```
   isfcr{REDACTED}
   ```

### Scripts

#### scripts/decode_zw.py

Decodes the zero-width symbols in a text file into bytes and prints the result. It reads `artifacts/zw_rules_flag.txt` by default, or the path given as the first argument. Run it from the challenge directory with `python3 work/scripts/decode_zw.py`.

```python
#!/usr/bin/env python3
"""Decode the zero-width steganography of the Cryovault Discord #rules message.

Symbols to 2 bits each: ZWNJ=00, ZWJ=01, POP(202C)=10, BOM(FEFF)=11.
Every hidden byte is written as four padding NUL symbols followed by four
payload symbols, so one in every two decoded bytes is 0x00 and is dropped.
"""
import sys
from pathlib import Path

BITS = {"\u200c": 0b00, "\u200d": 0b01, "\u202c": 0b10, "\ufeff": 0b11}


def decode(text: str) -> str:
    bits = []
    for ch in text:
        if ch in BITS:
            v = BITS[ch]
            bits.append((v >> 1) & 1)
            bits.append(v & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        if byte:
            out.append(byte)
    return out.decode("utf-8", "replace")


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent.parent / "artifacts" / "zw_rules_flag.txt"
    print(decode(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
```

### Notes

- The challenge has no `files/` directory. The only input is the Discord message, so the captured `artifacts/zw_rules_flag.txt` is the decoder's input and the source of truth.
- The message content is live data. If the artifact looks stale, re-read the "2. Flag Format" code span in #rules and rerun the decoder on the new text.
- The decoder drops every zero byte, not just every other one, so any padding in the payload is removed as well.
- Author hints in the Discord: "Look for flags in this discord server" and "#1 might require pc". The flag format is `isfcr{}`.
- Dead ends that did not help: the CTFd API on the platform hosts redirected every challenge endpoint to the login page and returned only the `.` description, and public OSINT on the author found no flag. Enumerating the Discord server (roles, emoji, stickers, channel names and topics, announcement embeds) also found nothing. The flag was only in the text of the #rules message.
- The raw artifact is not reproduced here because it encodes the flag.
