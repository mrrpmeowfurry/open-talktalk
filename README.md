# open-talktalk
[![Discord](https://img.shields.io/discord/SERVER_ID?label=Discord)](https://discord.gg/T5MF85vX5r)

basically i'm reverse engineering the [TalkTalk client](https://web.archive.org/web/20160319124007/http://cdn.th.garenanow.com/talktalk/installer/TalkTalk_FullInstall_th.exe) (2016-03-19)
, figuring out how it talked to
the servers, and building a new server + a patcher so the client connects to it
instead. the original servers are long gone so we make our own.

## why???
good question, i'm reviving it because it was a part of my childhood (2014-2017) when it was commonly used by minecraft servers at the time.
i met a lot of people there and it was an experience that i do not want to forget.

## current stage of open-talktalk

very early, mostly notes + a plan so far. nothing actually runs yet. a good chunk of the docs is me guessing stuff - see [docs/PROTOCOL.md](docs/PROTOCOL.md)
if something's wrong feel free to send a pull request.

- [x] cracked the login reply format + the crypto (it's XTEA-CBC, with a 1024-bit RSA key for the handshake)
- [ ] the login *send* side / pre-login handshake
- [ ] patcher (swap the client's RSA key for ours)
- [ ] actual working login server
- [ ] then the fun stuff: chat, rooms, all that


## how it works (quick version)

the client logs in over HTTP(S) with some JSON, then keeps a TCP connection open for chat and rooms.
the login stuff is XTEA encrypted and the key gets wrapped with an RSA key that's baked right into the .exe.

problem: the original server's private key is gone forever, so we can't just pretend to be garena.
so instead we **patch the client** to trust *our* RSA key, point it at *our* server, and rebuild the backend ourselves.

if you want the actual technical breakdown it's all in [docs/PROTOCOL.md](docs/PROTOCOL.md).


## legal bit, to prevent me from getting DMCA'd or sued

this project does NOT use garena's keys or servers. we generate our own keys.
and this project does not use any leaked source code. purely reverse engineered
with Ghidra.


## license

MIT (todo: add the file)
