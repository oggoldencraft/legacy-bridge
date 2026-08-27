# legacy-bridge — 1.6.4 to 1.7.2 Minecraft Proxy

> **Notice:** This project is an **unfinished community effort** and a work in progress. It is intended for offline testing and protocol experimentation. Expect bugs, unmapped packet IDs, or desyncs. Contributions are welcome!

`main.py` is a single-file Python proxy that sits between a **Minecraft 1.6.4 client** and a **Minecraft 1.7.2 server**. It translates network protocol packets in real time, remaps 1.7.2 blocks and items to 1.6.4 equivalents, and handles local encryption handshakes to allow legacy clients to play on newer server builds.

---

## Technical Features

* **Protocol & Packet Translation:** Translates 1.6.4 C2S packets into 1.7.2 VarInt-encoded streams, and unpacks 1.7.2 S2C packets (handling Zlib compression thresholds dynamically when enabled by the server).
* **Pure Python Standalone NBT Engine:** Custom zero-dependency NBT parser (`NBTTag`, `nbt_decompress`, `nbt_write_payload`) to parse slot NBT data, chest inventory clicking, and item metadata.
* **Block & Item Remapping:**
* Uses a flat, O(1) lookup array (`_REMAP_FLAT`) for fast block ID and metadata conversion.
* Remaps 1.7.2 content back to safe 1.6.4 visuals (e.g., Stained Glass $\rightarrow$ Glass, Acacia/Dark Oak $\rightarrow$ Oak, Podzol/Red Sand $\rightarrow$ Dirt/Sand, Packed Ice $\rightarrow$ Ice, and 1.7 Flowers $\rightarrow$ Roses).
* Remaps 1.7.2 fish variants (Salmon, Pufferfish, Clownfish) to Raw/Cooked Fish and falls back out-of-range items to sticks (`ID 280`).


* **Dynamic World & Chunk Rewriting:** Decompresses, rewrites block/meta IDs inside single-chunk (`0x33`) and chunk-bulk (`0x38`) payloads, and recompresses them on the fly.
* **DataWatcher Translation:** `translate_datawatcher()` converts 1.7.2 entity metadata streams into 1.6.4 format to keep mobs, dropped items, and player entity states compatible.
* **Network & Pass-Through Support:**
* Generates an on-the-fly RSA-1024 keypair with AES-CFB8 symmetric encryption for the 1.6.4 client handshake.
* Parses PROXY protocol v1 (ASCII) and v2 (Binary) headers.
* Handles BungeeCord server switching / re-joins via S2C Respawn (`0x09`) handling.



---

## Dependencies

Requires Python 3.x and the `cryptography` library for handling standard Minecraft RSA/AES-CFB8 encryption:

```bash
pip install cryptography

```

---

## Quick Start

1. Open `main.py` and set your target 1.7.2 server details:

```python
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 25564     # 1.6.4 Client connects here

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 25565     # 1.7.2 Server is here

```

2. Run the proxy:

```bash
python main.py

```

3. Connect your 1.6.4 Minecraft client to `localhost:25564`.

---

## Current Limitations & Known Issues

* **Offline Mode Only:** Online-mode Mojang session verification is not supported. The server must have `online-mode=false` (or run behind a local proxy network).
* **Forge Detection:** Forge strings (`\x00FML\x00`) are logged, but custom FML pipeline handshakes are not fully translated.
* **Particle Fallbacks:** World particles (`0x2A`) fall back to basic 1.6.4 `AuxSFX` (`0x3D`) events.
* **Statistics & Achievements:** Server statistics packets (`0x37`) are consumed and ignored.

---

## Contributing

PRs and fixes are welcome! Areas that need the most work:

1. Expanding block/item lookup tables in `_BLOCK_REMAP`.
2. Refining tile-entity and NBT payload mapping during window clicks.
3. Improving mob datawatcher mapping for 1.7-specific entities.

---

## License

This project is open-source under the [MIT License](https://github.com/oggoldencraft/legacy-bridge/blob/main/LICENSE).
