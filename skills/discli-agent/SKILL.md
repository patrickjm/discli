---
name: discli-agent
description: Use when operating the discli CLI/daemon for Discord workflows: auth login, daemon start/stop, chat send/read/reply, reactions, attachments, pings, guild/channel/user info, and unread thresholds.
---

# discli Agent Workflow

## Setup

- Store the Discord bot token once:
  - `discli auth login --token "$DISCLI_TOKEN"`
- Start the daemon when needed:
  - `discli daemon start --intents guilds,guild_messages,dm_messages,message_content`

## Chat operations

- Send a message:
  - `discli chat send -c <channel_id> -m "..."`
- Send with files:
  - `discli chat send -c <channel_id> -m "..." -f /path/file`
- Reply to a message:
  - `discli chat reply -c <channel_id> -r <message_id> -m "..."`
- Read recent messages (default resolves reply context):
  - `discli chat read -c <channel_id> -l 20`
  - `--no-replies` to skip reply resolution
  - `--all` to include read messages
  - `--mark` to advance unread threshold to the newest returned message
  - `--before <message_id>` for pagination

## Unread thresholds

- Show per-channel threshold:
  - `discli chat threshold -c <channel_id>`
- Update threshold:
  - `discli chat mark -c <channel_id> -m <message_id>`
  - `discli chat mark -c <channel_id> --latest`

## Reactions and emojis

- Add/remove reactions:
  - `discli chat react add -c <channel_id> -m <message_id> -e "😀"`
  - `discli chat react remove -c <channel_id> -m <message_id> -e "name:emoji_id"`
- List reactions:
  - `discli chat react list -c <channel_id> -m <message_id>`

## Attachments

- Download an attachment from a message:
  - `discli chat download -c <channel_id> -m <message_id> --attachment-id <id> --out /path/file`

## Mentions

- Mention specific users/roles with send/reply:
  - `--mention-user <id>` and `--mention-role <id>` (repeatable)
- Suppress mentions:
  - `--suppress-mentions`

## Pings

- List recent bot mentions:
  - `discli pings list -l 20`
- Resolve ping context (guild/channel names + link):
  - `discli pings context -l 20`
- Clear stored pings:
  - `discli pings clear`

## Metadata lookups

- Guilds: `discli info guilds`
- Channels in guild: `discli info channels -g <guild_id>`
- Single channel: `discli info channel -c <channel_id>`
- User: `discli info user -u <user_id>`

## Teardown

- Stop daemon when done:
  - `discli daemon stop`
