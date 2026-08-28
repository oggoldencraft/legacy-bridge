# legacy-bridge

A standalone Python proxy that translates network traffic between a Minecraft 1.6.4 client (protocol 78) and a Minecraft 1.7.2 server (protocol 4). It handles packet structure conversion, encryption handshakes, block and item ID remapping, DataWatcher translation, and chunk rewriting.

## Requirements

* Python 3.8 or newer
* `cryptography` library

Install dependencies with pip:

```bash
pip install cryptography
```

## Configuration & Usage

Proxy settings are configured directly in `main.py`:

```python
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 25564       # Port the 1.6.4 client connects to

TARGET_HOST = "127.0.0.1" # 1.7.2 server address
TARGET_PORT = 25565       # 1.7.2 server port

DEBUG = True
DEBUG_MOVEMENT = False    # Verbose movement packet logging
DEBUG_FORGE = True        # Plugin message / Forge channel logging
```

Run the proxy:

```bash
python main.py
```

Then point your 1.6.4 client to `localhost:25564`.

The target 1.7.2 server must have `online-mode=false` set in `server.properties` unless it is behind an authentication proxy.

## Features

### Protocol & Packet Handling
* **Handshake & Encryption:** Generates an RSA-1024 keypair to handle the 1.6.4 client login handshake, negotiates a shared secret, and switches to AES-CFB8 encryption.
* **VarInt & Compression:** Handles 1.7.2 VarInt framing and decompresses/compresses network packets when the server sets a Zlib compression threshold (packet `0x03`).
* **BungeeCord Support:** Handles sub-server transfers and dimension switching via S2C respawn packets (`0x09`).
* **PROXY Protocol:** Parses both v1 (text) and v2 (binary) PROXY protocol headers from load balancers (HAProxy, Nginx, Cloudflare Spectrum) to preserve original client IP addresses.
* **Server List Ping:** Intercepts legacy `0xFE` pings and queries the 1.7.2 server status, formatting MOTDs and player counts for the 1.6.4 multiplayer menu.

### World & Chunk Rewriting
* **O(1) Remapping Table:** Uses a flat 65,536-entry lookup array (`_REMAP_FLAT`) for fast block ID and metadata substitution inside single chunk (`0x33`) and chunk bulk (`0x38`) payloads.
* **Biome ID Clamping:** 1.6.4 clients crash when receiving biome IDs higher than 22. The chunk parser automatically rewrites unknown 1.7 biomes to Plains (ID 1).
* **NBT Translation:** Includes a pure-Python NBT parser/serializer (`NBTTag`) to rewrite block and item IDs inside tile entities and inventory slots without third-party NBT dependencies.

### Remapping Reference

| 1.7.2 Block / Item | Mapped 1.6.4 Equivalent |
| :--- | :--- |
| Stained Glass (`95:*`) | Glass (`20:0`) |
| Stained Glass Pane (`160:*`) | Glass Pane (`102:0`) |
| Acacia / Dark Oak Planks (`5:4`, `5:5`) | Oak Planks (`5:0`) |
| Acacia / Dark Oak Logs (`17:4`, `17:5`) | Oak Log (`17:0`) |
| Acacia / Dark Oak Leaves (`18:4`, `18:5`) | Oak Leaves (`18:0`) |
| Logs 2 / Leaves 2 (`161:*`, `162:*`) | Oak Log / Oak Leaves |
| Podzol (`3:2`) | Dirt (`3:0`) |
| Red Sand (`12:1`) | Sand (`12:0`) |
| Packed Ice (`174`) | Ice (`79:0`) |
| 1.7 Flowers (`38:1-9`) | Rose (`37:0`) |
| Double Plants (`175:*`) | Tallgrass (`31:1`) |
| Acacia / Dark Oak Stairs (`163`, `164`) | Oak Stairs (`53`) |
| Acacia / Dark Oak Slabs (`125`, `126`) | Oak Slabs (`125`, `126`) |
| Fish variants (`349`, `350` meta) | Raw Fish / Cooked Fish |
| Acacia Boat (`424`) | Boat (`333`) |
| Unmapped items (> 422) | Stick (`280`) |

### Entity & Metadata
* **DataWatcher Translation:** `translate_datawatcher()` translates 1.7 entity metadata streams back to 1.6 format, handling item slots, text fields, and entity flags.
* **Sound Mapping:** Maps 1.7 namespaced sounds (`game.player.hurt`, `entity.arrow.shoot`, etc.) back to legacy sound identifiers.
* **Particle Conversion:** Converts 1.7 particle packets (`0x2A`) into corresponding `AuxSFX` (`0x3D`) sound and particle effects where applicable.

## Known Limitations

* **No Online Mode Auth:** The proxy does not authenticate against Mojang session servers. The backend server must be running in offline mode.
* **Forge Handshakes:** Basic FML login packet structure is logged, but complex mod handshake channels are not fully mapped. This is intended primarily for vanilla clients and servers.
* **Statistics & Achievements:** S2C statistics packets (`0x37`) are discarded.

## License

MIT License. See `LICENSE` for details.
