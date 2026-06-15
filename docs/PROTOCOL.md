# talktalk protocol notes

my notes from reverse engineering `GarenaMessenger.exe` (the talktalk / garena
plus messenger client). all of this is from staring at it in ghidra + poking
the binaries with `strings` and `grep`. the servers are dead so nothing's been
tested against a real one. anything i say "probably/maybe/i think" is a guess,
not fact. if you know better, pr it.

heads up: this is the messenger client, which is newer than the old garena
room/game client that people reversed years ago (the "gcb" wc3/l4d tunneling
stuff). that old writeup is handy but it doesn't match this client. the old one
used AES, this one uses XTEA. the old one had a 2048-bit shared RSA key, this one
has a different 1024-bit key. and this client sends login as JSON, not the old
binary blobs. so use the old docs as a hint, not gospel.


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


## how it's put together

two stages, pretty standard for messengers of this era:

1. login over http(s). it uses wininet (`InternetConnectW`, `HttpOpenRequestW`,
   `HttpSendRequestW`, `HttpQueryInfoW`) and sends json creds to an auth endpoint.
2. after that it opens one long-lived tcp connection (`CPrimaryTcp`) that carries
   all the binary packets, chat, rooms, presence, everything. there's also a udp
   path (`CPrimaryUdp`) for nat punching / p2p / voice. it links the udt4 lib for
   the reliable-udp stuff.

### the "processor" list (this is basically the whole protocol's table of contents)

every message type has a c++ class under `ProcessorNS`, they all inherit from
`CBaseProcessor` and have a `Process(const char* buf, int len)`. i pulled the
full list out of the symbol table. just from the names you can see the whole
feature set:

auth / session:
- `CUserAuthPreLoginProcessor` (step 1 of the handshake)
- `CUserAuthLoginProcessor` (step 2, the login reply, this is the one i analysed)
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

todo: find the dispatcher in `tcpdatahandler.cpp` that maps opcode -> processor.
that's where the actual numeric packet ids live. probably look at how the
`CBaseProcessor` subclasses get registered / constructed.


## the crypto (i traced it in the disassembly woo hoo :clap:)

this is the most done part and it's the key to everything for a server.

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


## the http / json login

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
- the actual auth subdomain (like `something.garenanow.com`) is built in code by
  sticking a prefix in front of the base domain, so it's not one greppable string.
  todo: find that prefix.

### the json (confirmed, found the actual templates in the binary around offset ~8350560)

the client builds these json shapes, field names are straight from the binary:

```json
{"username":"...", "password":"...", "timestamp":"..."}   // login
{"uid":"...", ...}                                         // identity/session
// game/room stuff uses: "gameid", "isrealtime", "clan_id", "mode"
// password change uses: "old_pwd", "new_pwd"
```

so auth is json over http(s), and the body or session key is probably
rsa/symmetric wrapped. way easier to deal with than the old binary protocol.
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
3. point the client at our server. easiest is the hosts file mapping the auth
   subdomain to our ip (need to find the subdomain first). or patch the domain
   handling.
4. reverse the rest of the auth crypto (how the json/session key is wrapped,
   password hashing, the timestamp thing)
5. write the server:
   - http(s) endpoint that takes the json login
   - rsa decrypt the session key with our private key
   - check creds, build a valid login reply (status byte + 4/16/4 payload),
     xtea-cbc encrypted
   - tcp listener that speaks the primarytcp framing for after login
6. then build outward, keepalive, buddy list, chat, groups, one processor family
   at a time

first thing to actually aim for: get the real client to connect to a server we
control and just log the raw bytes. don't even worry about replying correctly
yet. seeing the real prelogin bytes show up makes everything after it way less
guessy.


## stuff i still need to figure out

- [ ] the opcode -> processor dispatch table in `tcpdatahandler.cpp` (gives the packet ids)
- [ ] reverse `CAuthLoginAction::PreAuthLogin` and `AuthLogin` (the send side).
      ghidra didn't label these, only rtti/strings, so reach them via xrefs from
      the `loginaction.cpp` string or the json templates
- [ ] how the xtea/aes session key is derived (`get_aes_key` + the uid mixing in
      `securitymanager.cpp`)
- [ ] how the password is hashed (md5? salt?)
- [ ] the auth subdomain prefix in front of `garenanow.com`
- [ ] the `CPrimaryTcp` framing (header size, endianness, where the opcode sits)
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

(also renamed a bunch of in-between wrapper functions: `Decrypt_Inner`,
`Decrypt_Wrapper3`, `Decrypt_Dispatch`, `Decrypt_Unwrap`, `Buffer_CopyRange`,
`Decrypt_BufferMgmt`)


## how i found this stuff (if you're new to RE and want to follow along)

- fastest way to find which binary has the code: `grep -l <some string you know is in it> *.exe *.dll`
- those `...\something.cpp` source paths are left in by the logging code and are
  the best ghidra anchors. search the string, follow its xref, you land in the function
- ghidra didn't name a lot of the c++ methods (only had rtti/vftable). you get to
  the real function through the class vftable (its entries are the methods) or by
  xref from a string the function uses
- use `Window -> Symbol Table` and UNCHECK "name only", it's way more reliable
  than the symbol tree filter
- rename everything the second you figure it out. the ghidra database basically
  becomes your notes
