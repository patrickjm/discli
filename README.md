# discli

`discli` is a local CLI and daemon for interacting with Discord.

## Quick start

1) Save your bot token:

```bash
DISCLI_TOKEN=... discli auth login --token "$DISCLI_TOKEN"
```

2) Start the daemon (auto-generates daemon token and saves it):

```bash
discli daemon start --intents guilds,guild_messages,dm_messages,message_content
```

3) Send a message:

```bash
discli chat send -c <channel_id> -m "hello"
```

## Install via Homebrew

```bash
brew install patrickjm/tap/discli
```

## Build from source

```bash
go build ./cmd/discli
```
