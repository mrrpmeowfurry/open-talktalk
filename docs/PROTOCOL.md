# talktalk protocol notes

my notes from reverse engineering `GarenaMessenger.exe` (the talktalk / garena
plus messenger client). a lot of this is from staring at it in ghidra + poking
the binaries with `strings` and `grep`, but a good chunk is now confirmed against
the **live client** (i redirected the dead hostname to my own machine with the
windows hosts file + a python tcp listener on port 9100). stuff marked "confirmed
live" came from real captured packets. anything i say "probably/maybe/i think" is
a guess, not fact. if you know better, pr it.

heads up: this is the messenger client, which is newer than the old garena
room/game client that people reversed years ago (the "gcb" wc3/l4d tunneling
stuff). that old writeup is handy but it doesn't match this client. the old one
used AES, this one uses XTEA. the old one had a 2048-bit shared RSA key, this one
has a different 1024-bit key. so use the old docs as a hint, not gospel.

also important: the http/json stuff is just config/version/status checks. the
ACTUAL login is the raw binary TCP connection (see below). don't get those mixed up.


## the big picture (how login actually works)

confirmed flow, from watching the live client:

1. on launch + login the client makes some http(s) calls for config / version /
   server status. these are just checks, not the login itself.
2. the real login is a **raw binary TCP connection** to
   **`live.imconnect.garenanow.com:9100`**. this is where all the actual auth +
   chat + everything happens.
3. that hostname is dead now, so the client can't connect -> Winsock error 10049
   -> shows "cannot connect with Garena+ server".

to talk to the client yourself: point `live.imconnect.garenanow.com` at your own
machine via the windows hosts file, run a tcp server on port 9100, and the client
connects straight to you. no http involved for this part.


## the connection target (CONFIRMED LIVE via x32dbg)

the client opens its real login socket to:

```
live.imconnect.garenanow.com : 9100
```

- these come from config keys `im_server_domain` and `im_server_port`, read at
  runtime. NOT a hardcoded string, NOT in any config file on disk, NOT in the
  downloaded xml configs — it's seeded at runtime somewhere.
- confirmed by breakpointing the config-load function in x32dbg and reading the
  returned value live. it was NOT empty like i first assumed — it literally
  returns `live.imconnect.garenanow.com`, and the port returns 9100.

### x32dbg address math (write this down)

ghidra assumes base `0x00400000`. the module actually loaded at `0x00B90000`. so:

```
runtime address = ghidra address + 0x790000
```

example: `IMServer_LoadConfig` at ghidra `0x0044c510` -> runtime `0x00BDC510`.


## where the code actually is

it's all in `GarenaMessenger.exe`, not `xIM.dll` like the `xim` naming makes you
think. found that with:

```
grep -l userauthlogin *.exe *.dll   # -> GarenaMessenger.exe
```

the binary still has a bunch of source paths baked in (the logging code leaks
them). these are gold for navigating in ghidra, search the string and follow the
xref:

```
.../im/imclient/imclient/logic/auth/userauthloginprocessor.cpp
.../im/imclient/imclient/action/loginaction.cpp
.../im/imclient/imclient/network/primarytcp.cpp
.../im/imclient/imclient/network/primaryudp.cpp
.../im/imclient/imclient/network/tcpdatahandler.cpp
.../im/imclient/imclient/security/securitymanager.cpp
```

also leaks the pdb path: `...\imclient\Release\GarenaMessenger.pdb`

other binaries in the install i haven't touched yet but matter later:

| file | what it probably does |
|------|------|
| `GarenaMessenger.exe` | main client, the thing i'm reversing |
| `Room/garena_room.exe` | the room |
| `bbtalk/BBTalk.exe` | voice chat |
| `libcurl.dll` / `ssleay32.dll` / `libeay32.dll` | http + openssl, the https auth |
| `HookSocket.dll` / `Room/SocketHook.dll` | socket hooking for game traffic |
| `MD5.dll` | md5, probably password hashing |
| `7za.dll` / `Zip7Module.dll` / `zlib1.dll` | unpacking archives / the Skin.ggz thing |
| `RSALib.dll` | rsa stuff for the key exchange |


## the TCP wire format (CONFIRMED LIVE)

every packet on the IM TCP connection is framed like:

```
[4-byte length, little-endian] [1-byte opcode] [payload...]
```

the length covers everything after the length field (opcode + payload).

confirmed live: username "evelyn" came through as
`0d000000 0a0100fc3000 6576656c796e00` — `0x0d` = 13 = the byte count after the
length field.

strings inside packets are **null-terminated plaintext**, no length prefix. the
reader literally reads bytes until it hits a `00` (confirmed from the string-reader
function: clear(), then loop push_back until byte == 0).


## the "processor" list (basically the protocol's table of contents)

every message type has a c++ class under `ProcessorNS`, they all inherit from
`CBaseProcessor` and have a `Process(const char* buf, int len)`. pulled the full
list out of the symbol table. just from the names you can see the whole feature set:

auth / session:
- `CUserAuthPreLoginProcessor` (step 1 of the handshake)
- `CUserAuthLoginProcessor` (step 2, the login reply, the one i analysed)
- `CUserAuthLoginInfoProcessor` (step 3, account info)
- `CRefreshTokenProcessor`, `CAccountSecurityProcessor`, `CVersionConfirmProcessor`

buddies / presence:
- `CBuddyListProcessor`, `CBuddyOnlineProcessor`, `CBuddyAddProcessor`,
  `CBuddyAddRequestProcessor`, `CBuddyAddTempProcessor`, `CBuddyRemoveProcessor`,
  `CBuddyBlockProcessor`, `CBuddyGameRemoveProcessor`, `CSuggestedBuddiesProcessor`
- buddy list categories: `CCateCreateResultProcessor`, `CCateChangeProcessor`,
  `CCateRemoveProcessor`, `CCateRenameProcessor`, `CCategoryProcessor`

chat (1:1, group, clan, temp group, each has a Confirm sibling for delivery acks):
- `CChatProcessor`, `CChatConfirmProcessor`
- `CGroupChatProcessor`, `CGroupChatConfirmProcessor`
- `CClanChatProcessor`, `CClanChatConfirmProcessor`
- `CTempGroupChatProcessor`, `CTempGroupChatConfirmProcessor`
- `CNudgeProcessor`, `CTypingStatusExProcessor`

groups / clans / temp groups (the "rooms"):
- `CGroupInfoProcessor`, `CGroupSimpleInfoProcessor`, `CGroupInviteProcessor`,
  `CGroupMemberJoinProcessor`, `CGroupMemberActionProcessor`,
  `CGetUserGroupsProcessor`, `CSystemGroupProcessor`
- `CClanInfoProcessor`, `CClanInviteProcessor`, `CClanMemberJoinProcessor`,
  `CClanMemberActionProcessor`, `CClanMemberStatusProcessor`,
  `CClanSearchProcessor`, `CNotifyClanProcessor`, `CGetUserClansProcessor`
- `CJoinTempGroupProcessor`, `CLeaveTempGroupProcessor`,
  `CRequestTempGroupIdProcessor`, `CAddTempGroupMemberProcessor`,
  `CGetUserTempGroupsProcessor`

udp / nat traversal / p2p:
- `CMakeHoleProcessor`, `CMakeHoleRequestProcessor`, `CAckMakeHoleProcessor`,
  `CMakeHoleAckProcessor`, `CUdpPingProcessor`, `CUdpPingAckProcessor`,
  `CUdpServerRelayProcessor`, `CP2PUdtProcessor`, `CRelayRegisterAckProcessor`,
  `CBaseUdpProcessor`, `CVoiceGroupUDPProcessor`, `CVoiceServerEchoProcessor`

user / misc / infra:
- `CUserInfoProcessor`, `CUserInfoByNameProcessor`, `CUserInfoListProcessor`,
  `CUserPersonalInfoProcessor`, `CUserGamesInfoProcessor`,
  `CUserChangeIconProcessor`, `CUserChangeNicknameProcessor`,
  `CUserChangeStatusProcessor`, `CUserSettingProcessor`,
  `CUserSettingRequestProcessor`, `CQueryUserOptionProcessor`,
  `CQueryMemberStatusProcessor`, `CGetRenameProcessor`, `CGetSignatureProcessor`
- `CGPPSelfInfoProcessor`, `CGPPBuddyInfoProcessor`, `CGCAInfoProcessor`,
  `CMiscInfoProcessor`, `CProductInfoProcessor`, `CPaymentResultProcessor`
- `CKeepAliveProcessor` (heartbeat), `CErrorProcessor` (server errors),
  `CExtendProcessor`, `CNotificationProcessor`, `CCcuUpdateProcessor`,
  `CXimCmdProcessor`, `CFileTransferExProcessor`,
  `COfflineFileUploadedProcessor`, `CBaseProcessor` (the base class)


## the dispatch table (opcode -> processor)

processors register themselves into a global table via `Dispatch_Register`
(ghidra `FUN_00a8f050`). each registration looks like:

```
opcode = 0xNN
table  = Dispatch_GetTable()        // FUN_00a8efb0
Dispatch_Register(table, opcode, processor_instance)
```

to get a processor's opcode: find its constructor, find who calls it (xref), that
caller has the `Dispatch_Register` line with the number.

known opcodes so far:
- `0x0a` -> pre-login (client->server)
- `0xee` -> CErrorProcessor
- `0xc1` -> CNotificationProcessor

**finding ALL the `Dispatch_Register` calls = the entire opcode table for every
processor.** that's the next big job and it unlocks every packet type at once.


## packets i've mapped

### pre-login (client -> server) — CONFIRMED LIVE

the very first packet the client sends after connecting. captured it by typing
different usernames and watching the bytes change.

```
[4-byte length] 0a 01 00 fc 30 00 <username>\0
```

- opcode `0x0a`
- fixed 6-byte header `0a 01 00 fc 30 00` (constant across every attempt)
- username as null-terminated ascii, plaintext

examples:
- "evelyn" -> `0d000000 0a0100fc3000 6576656c796e00`
- "lily"   -> `0b000000 0a0100fc3000 6c696c7900`

this is step 1, before any password. server is meant to reply with crypto/session
setup, THEN the client sends the password in a later packet (not captured yet).

### pre-login reply (server -> client) — format from ghidra

handler: `CUserAuthPreLoginProcessor::Process`. parsed as:

```
[opcode] [int] [int] [string] [string]
```

two ints, then two null-terminated strings. the two strings get fed into crypto
transforms (`FUN_007a06a0` / `FUN_0079c7e0`) — probably the key-exchange material.
haven't cracked what they should contain.

### error packet (server -> client) — CONFIRMED LIVE, opcode 0xee

handler: `CErrorProcessor::Process`. format:

```
[4-byte length] ee [4-byte error code, LE] [message bytes...]
```

- opcode `0xee` (registered via Dispatch_Register with 0xee)
- 4-byte error code feeds the `ProcessSignInError` switch
- the message bytes after the code are read plaintext BUT the client IGNORES them
  and shows its own built-in localized string for that code instead. so you do
  NOT get custom text out of this packet — you pick the code + which built-in
  message shows. client formats it as `[Error XXXX] <built-in message>`.

**this works pre-login.** send it right after the client's pre-login packet and it
pops a message box. confirmed on screen.

error code -> what the client shows (from ProcessSignInError):
- `0x11` -> "invalid version" (triggers update)
- `0x21` -> **"wrong username or password"** (confirmed live, the good one)
- `0x31` -> error + opens support url
- `0x52` -> generic login error
- `0x65` -> "insecure password" + opens account page
- `0x66` -> error + opens security center
- `0x70` -> "login parameter error"
- anything else (default) -> "cannot connect with Garena+ server"

### notification packet (server -> client) — format mapped, opcode 0xc1

handler: `CNotificationProcessor::Process`. format:

```
[4-byte length] c1 [4-byte count] (then 'count' notification items)
```

each item (some field sizes still guessed):
```
[1 byte type?] [4-byte int] [4-byte int] [1 byte] [1 byte] [string1]\0 [string2]\0
```

the two strings ARE displayed as-is (title + body) = this is the real custom-text
vector, unlike the error packet.

**BUT** it only displays when the client is logged in / in-session. sending a
`0xc1` packet pre-login does nothing — tested live, well-formed packet -> no popup.
so custom notification text needs the full login handshake working first.


## the crypto (traced it in the disassembly woo hoo :clap:)

this is the most done part and it's the key to everything for a server.

note: incoming pre-login / error / notification packets are NOT transport-encrypted
(confirmed live — plaintext packets i sent were processed fine). the XTEA-CBC stuff
applies to the auth login REPLY body specifically. still need to map exactly which
packets are encrypted vs plaintext.

### rsa key exchange

the client has a 1024-bit rsa public key embedded as plain PEM text.

it's at file offset `8350309` in `GarenaMessenger.exe`. here it is:

```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR7FHnzqB8syM62mAJAG7z6/ie
/Vz3eq0hEFHQCAd9xxQocrjDbulx1LNox5wTprvLibVRqDCMaPcXZMFRnerZC1YO
Ems2U3VwDMWi5s+B4qD+6jG1PB+NPzrlIt+asZtcDDkdmX1t5WgHMoubvV9tCOpH
YUBgF34S9lvbldXW4wIDAQAB
-----END PUBLIC KEY-----
```

it uses the windows crypto api for randomness: `CryptAcquireContextA`,
`CryptGenRandom`, `CryptReleaseContext`, `CryptEnumProvidersA`.

what i think happens (not 100% confirmed): client makes a random session key with
`CryptGenRandom`, encrypts it with that rsa public key, sends it during prelogin.
the real server had the matching private key and decrypted it. that private key
is gone forever, so for our own server we just swap this public key for one we
made (see the server plan below).

you can't pull the private key out of the client, that's the whole point of
public key crypto. and no, the old gcb private key doesn't work, totally
different key.

### the symmetric cipher is XTEA in CBC mode (confirmed)

the login reply body gets decrypted with XTEA, cbc mode. i traced it from
`CUserAuthLoginProcessor::Process` down through like 5 wrapper functions until i
hit the actual cipher.

the block function (i renamed it `XTEA_DecryptBlock`, was `FUN_007a0810`):

```c
undefined8 XTEA_DecryptBlock(uint v0, uint v1, int key) {
  uint sum = 0xC6EF3720;            // = delta * 32, decrypt starts here and counts down
  for (i = 0; i < 0x20; i++) {      // 32 rounds
    v1 -= (((v0<<4) ^ (v0>>5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    sum += 0x61C88647;              // = -delta, basically sum -= 0x9E3779B9
    v0 -= (((v1<<4) ^ (v1>>5)) + v1) ^ (sum + key[sum & 3]);
  }
  return (v1 << 32) | v0;
}
```

it's textbook XTEA, the constants give it away:
- delta is `0x9E3779B9` (the magic xtea number). `0xC6EF3720` is that times 32,
  and `0x61C88647` is negative delta.
- 32 rounds
- 64-bit block (two 32-bit little endian words)
- 128-bit key, read as 4 words `key[0..3]`

the cbc part (renamed `Decrypt_CBC`, was `FUN_007a0b40`):
- ciphertext length has to be a multiple of 8
- decrypts block by block, xors each decrypted block with the previous ciphertext
  block (normal cbc)
- padding: last byte = how many pad bytes there are (1 to 8), and all the pad
  bytes have to equal that number. if the padding's wrong it returns 0, which the
  client logs as "decrypt error!"

still don't know where the xtea key comes from. there's a
`SecurityNS::get_aes_key()` and a funny error string "my uid is 0, this will
cause the error in encoding and decoding", which makes me think the key gets
mixed with your user id somehow. there's also an aes path next to the xtea one.
todo: figure out how the session key is actually derived.

### text encodings i spotted

- base64 alphabet near the rsa/pem code
- a base62 alphabet and a hex alphabet near `securitymanager.cpp`, probably for
  encoding tokens/keys as text


## the http / json login (the config/check side, NOT the real login)

### transport

wininet http. the function that calls `InternetConnectW` picks the port like:
- default 80 (`0x50`)
- 443 (`0x1BB`) if some scheme field == 4 (so, https)
- or a custom port if one's set

the server hostname isn't a hardcoded string. it gets read out of a config
object (field at `+0xC4`) and built from a base domain.

### the domain

- config key is `garenanow_base_domian` (yes the typo "domian" is in the actual
  binary lol)
- base domain is `garenanow.com` (confirmed from subdomains in the room language
  xmls: `cdn.garenanow.com`, `ad.garenanow.com`)
- also saw `sng.garena.com` and `forum.sng.garena.com`
- the actual auth subdomain is built in code by sticking a prefix in front of the
  base domain, so it's not one greppable string. todo: find that prefix.

http config hosts the client hits on launch/login:
- `cdn.garenanow.com/im/config/*.xml` (config, STILL ALIVE, serves real files)
- `updateres.garenanow.com/im/versions.xml` (version, dead)
- `imcheck.garenanow.com/serverstatus.php` (status, hit on login, dead)

### the json (confirmed, found the actual templates in the binary around offset ~8350560)

the client builds these json shapes, field names are straight from the binary:

```json
{"username":"...", "password":"...", "timestamp":"..."}   // login
{"uid":"...", ...}                                         // identity/session
// game/room stuff uses: "gameid", "isrealtime", "clan_id", "mode"
// password change uses: "old_pwd", "new_pwd"
```

todo: figure out exactly what's encrypted and how the password is hashed (md5 is
linked, old client used plain md5 hex, need to verify).


## the login reply packet (confirmed layout)

from `CUserAuthLoginProcessor::Process` (i renamed it `LoginProcessor_Process`,
was `FUN_00456790`):

1. it's `Process(const char* buf, int len)`. `buf[0]` looks like the opcode, the
   body that gets decrypted is `buf+1` to `buf+len`.
2. body gets decrypted/verified (xtea-cbc). if it fails it logs "decrypt error!"
   and bails.
3. checks a status byte at object offset `0xDC` (`Login_GetResultByte`,
   `FUN_00456be0`). nonzero = success, zero = rejected.
4. on success it reads the payload in order with fixed-size readers:

| order | reader (my name) | size | what i think it is |
|-------|------|------|------|
| 1 | `PacketReader_Read4Bytes` (`FUN_00458030`) | 4 bytes | user id |
| 2 | `PacketReader_Read16Bytes` (`FUN_004581f0`) | 16 bytes | session token / key |
| 3 | `PacketReader_Read4Bytes` (`FUN_00458030`) | 4 bytes | server id / timestamp / flags |

the two readers are the same function basically, just different sizes. they keep
a cursor (first field of the reader object) and bounds check, throwing "Buffer is
Too small, can not Read the variable." if you run off the end.

also found `CStatusManager::AuthLoginIn(string, vector<unsigned char>, unsigned
char)`. that's string + byte vector + byte, which lines up perfectly with
(username/id) + (16-byte token) + (status byte). probably where the login result
gets stored into the client's session state.


## plan for the actual server

dependency order. none of this is built yet, it's just the plan.

1. generate our own 1024-bit rsa keypair, keep the private key on the server
2. patch the client's embedded public key (offset `8350309`) with ours. keep it
   1024-bit so the length stuff doesn't break, or patch the length fields too.
   this is the patcher tool.
3. point the client at our server. for the IM tcp side this already works via the
   hosts file (`live.imconnect.garenanow.com` -> our ip, port 9100). still need
   the http auth subdomain for the http side.
4. reverse the rest of the auth crypto (how the json/session key is wrapped,
   password hashing, the timestamp thing, the pre-login reply key exchange)
5. write the server:
   - tcp listener on 9100 speaking the framing `[4-byte len][opcode][payload]`
   - answer the `0x0a` pre-login, do the key exchange, accept the password
   - build a valid login reply (status byte + 4/16/4 payload), xtea-cbc encrypted
   - http(s) endpoint for the json side if needed
6. then build outward, keepalive, buddy list, chat, groups, one processor family
   at a time

already done: get the real client to connect to a server we control and log the
raw bytes (the prelogin packet). that made everything after it way less guessy.


## stuff i still need to figure out

- [ ] the FULL opcode -> processor dispatch table (all `Dispatch_Register` calls).
      i have the mechanism + 3 opcodes (0x0a, 0xee, 0xc1), need the rest
- [ ] the pre-login reply / key exchange (the two crypto strings) so the client
      proceeds to send the password
- [ ] the password packet (client -> send side, not captured yet)
- [ ] reverse `CAuthLoginAction::PreAuthLogin` and `AuthLogin` (the send side).
      ghidra didn't label these, only rtti/strings, so reach them via xrefs from
      the `loginaction.cpp` string or the json templates
- [ ] how the xtea/aes session key is derived (`get_aes_key` + the uid mixing in
      `securitymanager.cpp`)
- [ ] how the password is hashed (md5? salt?)
- [ ] the auth subdomain prefix in front of `garenanow.com`
- [ ] which packets are encrypted vs plaintext (error/notify/prelogin are plaintext,
      auth reply is xtea, need the full map)
- [ ] whether that 16-byte reply field is a token or a key


## functions i renamed in ghidra (so i don't lose them next session)

| address | was | renamed to | what it is |
|---------|----------|---------|------------|
| `0x00456790` | `FUN_00456790` | `LoginProcessor_Process` | `CUserAuthLoginProcessor::Process` |
| `0x00456be0` | `FUN_00456be0` | `Login_GetResultByte` | reads the status byte at `+0xDC` |
| `0x00456b90` | `FUN_00456b90` | `LoginData_Init` | zeros out the login result struct |
| `0x00458030` | `FUN_00458030` | `PacketReader_Read4Bytes` | reads 4 bytes, advances cursor |
| `0x004581f0` | `FUN_004581f0` | `PacketReader_Read16Bytes` | reads 16 bytes, advances cursor |
| `0x00457da0` | `FUN_00457da0` | `Decrypt_Wrapper` | decrypt entry wrapper |
| `0x007a0b40` | `FUN_007a0b40` | `Decrypt_CBC` | xtea-cbc + padding check |
| `0x007a0810` | `FUN_007a0810` | `XTEA_DecryptBlock` | the actual xtea, 32 rounds |
| `0x0044c510` | `FUN_0044c510` | `IMServer_LoadConfig` | reads im_server_domain + im_server_port (runtime 0x00BDC510) |
| `0x005dc180` | `FUN_005dc180` | `Config_GetString` | config key -> value, returns "" if missing |
| `0x00a8f050` | `FUN_00a8f050` | `Dispatch_Register` | table[opcode] = processor |
| `0x00a8efb0` | `FUN_00a8efb0` | `Dispatch_GetTable` | returns the dispatch table |
| `0x00456360` | `FUN_00456360` | `PreLoginProcessor_Process` | parses prelogin reply [int][int][str][str] |
| `0x004c0e40` | `FUN_004c0e40` | `ErrorProcessor_Process` | parses 0xee error packet |
| `0x004c1fa0` | `FUN_004c1fa0` | `Register_ErrorProcessor` | registers 0xee |
| `0x004c20e0` | `FUN_004c20e0` | `NotificationProcessor_Process` | 0xc1 entry |
| `0x004c2140` | `FUN_004c2140` | `NotificationProcessor_Process_Impl` | parses the notify list |
| `0x004c2a70` | `FUN_004c2a70` | `NotifyList_Parse` | reads count + loops items |
| `0x004c36a0` | `FUN_004c36a0` | `Notification_ParseItem_Impl` | reads item fields + 2 strings |
| `0x004c3e40` | `FUN_004c3e40` | `Register_NotificationProcessor` | registers 0xc1 |
| `0x004566d0` | `FUN_004566d0` | `PacketReader_ReadString` | null-terminated string reader |

(also renamed a bunch of in-between wrapper functions: `Decrypt_Inner`,
`Decrypt_Wrapper3`, `Decrypt_Dispatch`, `Decrypt_Unwrap`, `Buffer_CopyRange`,
`Decrypt_BufferMgmt`)


## how i found this stuff (if you're new to RE and want to follow along)

- fastest way to find which binary has the code: `grep -l <some string you know is in it> *.exe *.dll`
- those `...\something.cpp` source paths are left in by the logging code and are
  the best ghidra anchors. search the string, follow its xref, you land in the function
- ghidra didn't name a lot of the c++ methods (only had rtti/vftable). you get to
  the real function through the class vftable (its entries are the methods) or by
  xref from a string the function uses. slot [2] in the vftable was usually Process
- to find a packet's opcode: find the processor's constructor, find who calls it
  (xref), that caller has the `Dispatch_Register(table, opcode, ...)` line
- use `Window -> Symbol Table` and UNCHECK "name only", it's way more reliable
  than the symbol tree filter
- for live capture: hosts file redirect + a dumb python tcp listener on the port.
  print what the client sends, reply with guessed packets, watch what it does.
  that's how i got the framing, the prelogin packet, and the wrong-password error
- x32dbg to watch values live: breakpoint the function, F8 to step over, read the
  registers/stack. that's how i found the real server domain was
  `live.imconnect.garenanow.com` and the port 9100
- rename everything the second you figure it out. the ghidra database basically
  becomes your notes