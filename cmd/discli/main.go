package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickjm/discli/internal/client"
	"github.com/patrickjm/discli/internal/config"
	"github.com/patrickjm/discli/internal/daemon"

	"github.com/bwmarrin/discordgo"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	root := &cobra.Command{
		Use:           "discli",
		Short:         "CLI for controlling a local Discord daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	var (
		cfgPath  string
		addrFlag string
		authFlag string
		stateFlg string
		timeout  time.Duration
		jsonOut  bool
	)

	root.PersistentFlags().StringVar(&cfgPath, "config", config.DefaultConfigPath(), "config file path")
	root.PersistentFlags().StringVar(&addrFlag, "addr", "", "daemon address")
	root.PersistentFlags().StringVar(&authFlag, "daemon-token", "", "daemon auth token")
	root.PersistentFlags().StringVar(&stateFlg, "state", "", "daemon state path")
	root.PersistentFlags().DurationVarP(&timeout, "timeout", "t", config.DefaultTimeout, "request timeout")
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "output json")

	root.Version = fmt.Sprintf("%s (%s)", version, commit)
	root.SetVersionTemplate("{{.Version}}\n")

	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		config.ApplyEnv(&cfg)
		if addrFlag != "" {
			cfg.DaemonAddr = addrFlag
		}
		if authFlag != "" {
			cfg.DaemonToken = authFlag
		}
		if stateFlg != "" {
			cfg.StatePath = stateFlg
		}
		if timeout > 0 {
			cfg.Timeout = timeout
		}
		config.ApplyDefaults(&cfg)
		cmd.SetContext(context.WithValue(cmd.Context(), cfgKey{}, cfg))
		cmd.SetContext(context.WithValue(cmd.Context(), jsonKey{}, jsonOut))
		return nil
	}

	root.AddCommand(newDaemonCmd())
	root.AddCommand(newChatCmd())
	root.AddCommand(newInfoCmd())
	root.AddCommand(newPingsCmd())
	root.AddCommand(newAuthCmd())
	root.AddCommand(newConfigCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

type cfgKey struct{}

type jsonKey struct{}

func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Check daemon connectivity",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "ping",
		Short: "Ping the daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			if err := cli.Ping(ctx); err != nil {
				return err
			}
			return output(cmd, map[string]string{"status": "ok"}, "ok")
		},
	})
	cmd.AddCommand(newDaemonStartCmd())
	cmd.AddCommand(newDaemonStopCmd())
	cmd.AddCommand(newDaemonStatusCmd())
	cmd.AddCommand(newDaemonRunCmd())
	cmd.AddCommand(newDaemonSuperviseCmd())
	return cmd
}

func newChatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat",
		Short: "Send or read messages",
	}
	cmd.AddCommand(newChatSendCmd())
	cmd.AddCommand(newChatReplyCmd())
	cmd.AddCommand(newChatReadCmd())
	cmd.AddCommand(newChatMarkCmd())
	cmd.AddCommand(newChatThresholdCmd())
	cmd.AddCommand(newChatReactCmd())
	cmd.AddCommand(newChatDownloadCmd())
	return cmd
}

func newChatSendCmd() *cobra.Command {
	var channelID string
	var content string
	var files []string
	var mentionUsers []string
	var mentionRoles []string
	var suppressMentions bool

	cmd := &cobra.Command{
		Use:   "send",
		Short: "Send a message",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			req := client.SendRequest{
				ChannelID:        channelID,
				Content:          content,
				MentionUserIDs:   mentionUsers,
				MentionRoleIDs:   mentionRoles,
				SuppressMentions: suppressMentions,
			}
			var resp client.SendResponse
			var err error
			if len(files) > 0 {
				resp, err = cli.SendMessageWithFiles(ctx, req, files)
			} else {
				resp, err = cli.SendMessage(ctx, req)
			}
			if err != nil {
				return err
			}
			return output(cmd, resp, fmt.Sprintf("sent %s", resp.Message.ID))
		},
	}

	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().StringVarP(&content, "message", "m", "", "message content")
	cmd.Flags().StringSliceVarP(&files, "file", "f", nil, "file path to upload (repeatable)")
	cmd.Flags().StringSliceVar(&mentionUsers, "mention-user", nil, "user id to mention (repeatable)")
	cmd.Flags().StringSliceVar(&mentionRoles, "mention-role", nil, "role id to mention (repeatable)")
	cmd.Flags().BoolVar(&suppressMentions, "suppress-mentions", false, "suppress all mentions in content")
	_ = cmd.MarkFlagRequired("channel")
	return cmd
}

func newChatReplyCmd() *cobra.Command {
	var channelID string
	var messageID string
	var content string
	var failIfMissing bool
	var files []string
	var mentionUsers []string
	var mentionRoles []string
	var suppressMentions bool

	cmd := &cobra.Command{
		Use:   "reply",
		Short: "Reply to a message",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			req := client.ReplyRequest{
				ChannelID:        channelID,
				MessageID:        messageID,
				Content:          content,
				FailIfNotExist:   failIfMissing,
				MentionUserIDs:   mentionUsers,
				MentionRoleIDs:   mentionRoles,
				SuppressMentions: suppressMentions,
			}
			var resp client.ReplyResponse
			var err error
			if len(files) > 0 {
				resp, err = cli.SendReplyWithFiles(ctx, req, files)
			} else {
				resp, err = cli.SendReply(ctx, req)
			}
			if err != nil {
				return err
			}
			return output(cmd, resp, fmt.Sprintf("replied %s", resp.Message.ID))
		},
	}

	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().StringVarP(&messageID, "message-id", "r", "", "message id to reply to")
	cmd.Flags().StringVarP(&content, "message", "m", "", "message content")
	cmd.Flags().StringSliceVarP(&files, "file", "f", nil, "file path to upload (repeatable)")
	cmd.Flags().StringSliceVar(&mentionUsers, "mention-user", nil, "user id to mention (repeatable)")
	cmd.Flags().StringSliceVar(&mentionRoles, "mention-role", nil, "role id to mention (repeatable)")
	cmd.Flags().BoolVar(&suppressMentions, "suppress-mentions", false, "suppress all mentions in content")
	cmd.Flags().BoolVar(&failIfMissing, "fail-if-missing", false, "fail if referenced message is missing")
	_ = cmd.MarkFlagRequired("channel")
	_ = cmd.MarkFlagRequired("message-id")
	return cmd
}

func newChatReadCmd() *cobra.Command {
	var channelID string
	var limit int
	var before string
	var all bool
	var mark bool
	var noReplies bool

	cmd := &cobra.Command{
		Use:   "read",
		Short: "Read recent messages",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.ReadMessages(ctx, channelID, limit, before, !all, mark, !noReplies)
			if err != nil {
				return err
			}
			return output(cmd, resp, fmt.Sprintf("%d messages", len(resp.Messages)))
		},
	}

	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().IntVarP(&limit, "limit", "l", 20, "message limit (1-100)")
	cmd.Flags().StringVar(&before, "before", "", "message id to paginate before")
	cmd.Flags().BoolVar(&all, "all", false, "include already-read messages")
	cmd.Flags().BoolVar(&mark, "mark", false, "advance unread threshold to newest returned message")
	cmd.Flags().BoolVar(&noReplies, "no-replies", false, "disable reply context resolution")
	_ = cmd.MarkFlagRequired("channel")
	return cmd
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage local config",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Write a default config file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()
			config.ApplyEnv(&cfg)
			config.ApplyDefaults(&cfg)
			cfgPath := cmd.Flag("config").Value.String()
			if err := config.Save(cfgPath, cfg); err != nil {
				return err
			}
			return output(cmd, map[string]string{"config": cfgPath}, fmt.Sprintf("wrote %s", cfgPath))
		},
	})
	return cmd
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage Discord credentials",
	}
	cmd.AddCommand(newAuthLoginCmd())
	return cmd
}

func newAuthLoginCmd() *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store the Discord bot token in config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cmd.Flag("config").Value.String())
			if err != nil {
				return err
			}
			config.ApplyEnv(&cfg)
			if token == "" {
				return errors.New("token is required")
			}
			cfg.Token = token
			config.ApplyDefaults(&cfg)
			if err := config.Save(cmd.Flag("config").Value.String(), cfg); err != nil {
				return err
			}
			return output(cmd, map[string]string{"status": "saved"}, "saved")
		},
	}
	cmd.Flags().StringVarP(&token, "token", "t", "", "discord bot token")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

func newInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Query Discord metadata",
	}
	cmd.AddCommand(newInfoGuildsCmd())
	cmd.AddCommand(newInfoGuildCmd())
	cmd.AddCommand(newInfoChannelsCmd())
	cmd.AddCommand(newInfoChannelCmd())
	cmd.AddCommand(newInfoUserCmd())
	return cmd
}

func newInfoGuildsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "guilds",
		Short: "List guilds",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.ListGuilds(ctx)
			if err != nil {
				return err
			}
			if cmd.Context().Value(jsonKey{}).(bool) {
				return output(cmd, resp, "")
			}
			for _, g := range resp.Guilds {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", g.ID, g.Name)
			}
			return nil
		},
	}
}

func newInfoGuildCmd() *cobra.Command {
	var guildID string
	cmd := &cobra.Command{
		Use:   "guild",
		Short: "Get guild details",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.GetGuild(ctx, guildID)
			if err != nil {
				return err
			}
			if cmd.Context().Value(jsonKey{}).(bool) {
				return output(cmd, resp, "")
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", guildID)
			return nil
		},
	}
	cmd.Flags().StringVarP(&guildID, "guild", "g", "", "guild id")
	_ = cmd.MarkFlagRequired("guild")
	return cmd
}

func newInfoChannelsCmd() *cobra.Command {
	var guildID string
	cmd := &cobra.Command{
		Use:   "channels",
		Short: "List channels in a guild",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.ListChannels(ctx, guildID)
			if err != nil {
				return err
			}
			if cmd.Context().Value(jsonKey{}).(bool) {
				return output(cmd, resp, "")
			}
			for _, ch := range resp.Channels {
				id, _ := ch["id"].(string)
				name, _ := ch["name"].(string)
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", id, name)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&guildID, "guild", "g", "", "guild id")
	_ = cmd.MarkFlagRequired("guild")
	return cmd
}

func newInfoChannelCmd() *cobra.Command {
	var channelID string
	cmd := &cobra.Command{
		Use:   "channel",
		Short: "Get channel details",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.GetChannel(ctx, channelID)
			if err != nil {
				return err
			}
			return output(cmd, resp, fmt.Sprintf("channel %s", channelID))
		},
	}
	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	_ = cmd.MarkFlagRequired("channel")
	return cmd
}

func newInfoUserCmd() *cobra.Command {
	var userID string
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Get user details",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.GetUser(ctx, userID)
			if err != nil {
				return err
			}
			return output(cmd, resp, fmt.Sprintf("user %s", userID))
		},
	}
	cmd.Flags().StringVarP(&userID, "user", "u", "", "user id")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func newPingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pings",
		Short: "Show recent mentions of the bot",
	}
	cmd.AddCommand(newPingsListCmd())
	cmd.AddCommand(newPingsContextCmd())
	cmd.AddCommand(newPingsClearCmd())
	return cmd
}

func newPingsListCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recent pings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.ListPings(ctx, limit)
			if err != nil {
				return err
			}
			if cmd.Context().Value(jsonKey{}).(bool) {
				return output(cmd, resp, "")
			}
			for _, ping := range resp.Pings {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", ping.GuildID, ping.ChannelID, ping.MessageID, ping.Author)
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "l", 20, "max pings to return")
	return cmd
}

func newPingsClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Clear stored pings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			if err := cli.ClearPings(ctx); err != nil {
				return err
			}
			return output(cmd, map[string]string{"status": "cleared"}, "cleared")
		},
	}
}

func newPingsContextCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "context",
		Short: "List pings with location context",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.ListPingsResolved(ctx, limit)
			if err != nil {
				return err
			}
			if cmd.Context().Value(jsonKey{}).(bool) {
				return output(cmd, resp, "")
			}
			for _, ping := range resp.Pings {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", ping.GuildName, ping.ChannelName, ping.Author, ping.Link)
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "l", 20, "max pings to return")
	return cmd
}

func newChatMarkCmd() *cobra.Command {
	var channelID string
	var messageID string
	var latest bool

	cmd := &cobra.Command{
		Use:   "mark",
		Short: "Upsert the unread threshold for a channel",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			target := messageID
			if latest {
				resp, err := cli.ReadMessages(ctx, channelID, 1, "", false, false, false)
				if err != nil {
					return err
				}
				if len(resp.Messages) == 0 {
					return errors.New("no messages to mark")
				}
				target = resp.Messages[0].ID
			}
			if target == "" {
				return errors.New("message id is required unless --latest is set")
			}
			resp, err := cli.UpsertThreshold(ctx, channelID, target)
			if err != nil {
				return err
			}
			return output(cmd, resp, fmt.Sprintf("threshold set to %s", resp.ThresholdID))
		},
	}

	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().StringVarP(&messageID, "message", "m", "", "message id to mark as read")
	cmd.Flags().BoolVar(&latest, "latest", false, "mark the most recent message as read")
	_ = cmd.MarkFlagRequired("channel")
	return cmd
}

func newChatThresholdCmd() *cobra.Command {
	var channelID string
	cmd := &cobra.Command{
		Use:   "threshold",
		Short: "Show the unread threshold for a channel",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.GetThreshold(ctx, channelID)
			if err != nil {
				return err
			}
			return output(cmd, resp, fmt.Sprintf("threshold %s", resp.ThresholdID))
		},
	}
	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	_ = cmd.MarkFlagRequired("channel")
	return cmd
}

func newChatReactCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "react",
		Short: "Manage reactions on a message",
	}
	cmd.AddCommand(newChatReactAddCmd())
	cmd.AddCommand(newChatReactRemoveCmd())
	cmd.AddCommand(newChatReactListCmd())
	return cmd
}

func newChatReactAddCmd() *cobra.Command {
	var channelID string
	var messageID string
	var emoji string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a reaction",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			if err := cli.AddReaction(ctx, channelID, messageID, emoji); err != nil {
				return err
			}
			return output(cmd, map[string]string{"status": "ok"}, "ok")
		},
	}
	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().StringVarP(&messageID, "message-id", "m", "", "message id")
	cmd.Flags().StringVarP(&emoji, "emoji", "e", "", "emoji (unicode or name:id)")
	_ = cmd.MarkFlagRequired("channel")
	_ = cmd.MarkFlagRequired("message-id")
	_ = cmd.MarkFlagRequired("emoji")
	return cmd
}

func newChatReactRemoveCmd() *cobra.Command {
	var channelID string
	var messageID string
	var emoji string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove your reaction",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			if err := cli.RemoveReaction(ctx, channelID, messageID, emoji); err != nil {
				return err
			}
			return output(cmd, map[string]string{"status": "ok"}, "ok")
		},
	}
	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().StringVarP(&messageID, "message-id", "m", "", "message id")
	cmd.Flags().StringVarP(&emoji, "emoji", "e", "", "emoji (unicode or name:id)")
	_ = cmd.MarkFlagRequired("channel")
	_ = cmd.MarkFlagRequired("message-id")
	_ = cmd.MarkFlagRequired("emoji")
	return cmd
}

func newChatReactListCmd() *cobra.Command {
	var channelID string
	var messageID string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List reactions on a message",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			resp, err := cli.ListReactions(ctx, channelID, messageID)
			if err != nil {
				return err
			}
			if cmd.Context().Value(jsonKey{}).(bool) {
				return output(cmd, resp, "")
			}
			for _, react := range resp.Reactions {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%d\n", react.Emoji, react.Count)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().StringVarP(&messageID, "message-id", "m", "", "message id")
	_ = cmd.MarkFlagRequired("channel")
	_ = cmd.MarkFlagRequired("message-id")
	return cmd
}

func newChatDownloadCmd() *cobra.Command {
	var channelID string
	var messageID string
	var attachmentID string
	var index int
	var outPath string
	var outDir string
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download an attachment from a message",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			msgResp, err := cli.GetMessage(ctx, channelID, messageID)
			if err != nil {
				return err
			}
			att, err := selectAttachment(msgResp.Message.Attachments, attachmentID, index)
			if err != nil {
				return err
			}
			target := outPath
			if target == "" {
				if outDir == "" {
					outDir = "."
				}
				target = filepath.Join(outDir, att.Filename)
			}
			return downloadToFile(att.URL, target)
		},
	}
	cmd.Flags().StringVarP(&channelID, "channel", "c", "", "channel id")
	cmd.Flags().StringVarP(&messageID, "message-id", "m", "", "message id")
	cmd.Flags().StringVar(&attachmentID, "attachment-id", "", "attachment id")
	cmd.Flags().IntVar(&index, "index", -1, "attachment index (0-based)")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "output file path")
	cmd.Flags().StringVar(&outDir, "dir", "", "output directory")
	_ = cmd.MarkFlagRequired("channel")
	_ = cmd.MarkFlagRequired("message-id")
	return cmd
}

func newDaemonStartCmd() *cobra.Command {
	var background bool
	var supervise bool
	var tokenFlag string
	var intents string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			if tokenFlag != "" {
				cfg.Token = tokenFlag
			}
			if intents == "" {
				intents = "guilds,guild_messages,dm_messages"
			}
			if cfg.DaemonToken == "" {
				token, err := generateToken(32)
				if err != nil {
					return err
				}
				cfg.DaemonToken = token
				cfgPath := cmd.Flag("config").Value.String()
				if err := config.Save(cfgPath, cfg); err != nil {
					return err
				}
			}
			if background {
				return spawnSupervisor(cmd, cfg, intents, supervise)
			}
			if supervise {
				return superviseLoop(cmd.Context(), cfg, intents)
			}
			return runDaemonOnce(cmd.Context(), cfg, intents)
		},
	}
	cmd.Flags().BoolVar(&background, "background", true, "run daemon in background")
	cmd.Flags().BoolVar(&supervise, "supervise", true, "restart daemon on crash")
	cmd.Flags().StringVar(&tokenFlag, "token", "", "discord bot token (overrides config)")
	cmd.Flags().StringVar(&intents, "intents", "", "comma-separated intents")
	return cmd
}

func newDaemonStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			if err := cli.Shutdown(ctx); err != nil {
				return err
			}
			return output(cmd, map[string]string{"status": "stopped"}, "stopped")
		},
	}
}

func newDaemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check daemon status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()
			if err := cli.Ping(ctx); err != nil {
				return err
			}
			return output(cmd, map[string]string{"status": "running"}, "running")
		},
	}
}

func newDaemonRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "run",
		Short:  "Run the daemon in the foreground",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			intents := cmd.Flag("intents").Value.String()
			if intents == "" {
				intents = "guilds,guild_messages,dm_messages"
			}
			return runDaemonOnce(cmd.Context(), cfg, intents)
		},
	}
	cmd.Flags().String("intents", "", "comma-separated intents")
	return cmd
}

func newDaemonSuperviseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "supervise",
		Short:  "Supervise the daemon",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cmd.Context().Value(cfgKey{}).(config.Config)
			intents := cmd.Flag("intents").Value.String()
			if intents == "" {
				intents = "guilds,guild_messages,dm_messages"
			}
			return superviseLoop(cmd.Context(), cfg, intents)
		},
	}
	cmd.Flags().String("intents", "", "comma-separated intents")
	return cmd
}

func runDaemonOnce(ctx context.Context, cfg config.Config, intents string) error {
	intentValue, err := parseIntents(intents)
	if err != nil {
		return err
	}
	return runEmbeddedDaemon(ctx, cfg, intentValue)
}

func superviseLoop(ctx context.Context, cfg config.Config, intents string) error {
	intentValue, err := parseIntents(intents)
	if err != nil {
		return err
	}
	backoff := time.Second
	for {
		err := runEmbeddedDaemon(ctx, cfg, intentValue)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func runEmbeddedDaemon(ctx context.Context, cfg config.Config, intents discordgo.Intent) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()
	return daemon.Run(ctx, cfg.Token, cfg.DaemonAddr, cfg.DaemonToken, cfg.StatePath, intents)
}

func spawnSupervisor(cmd *cobra.Command, cfg config.Config, intents string, supervise bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"daemon"}
	if supervise {
		args = append(args, "supervise")
	} else {
		args = append(args, "run")
	}
	args = append(args, "--config", cmd.Flag("config").Value.String(), "--intents", intents)
	if cfg.DaemonAddr != "" {
		args = append(args, "--addr", cfg.DaemonAddr)
	}
	if cfg.DaemonToken != "" {
		args = append(args, "--daemon-token", cfg.DaemonToken)
	}
	if cfg.StatePath != "" {
		args = append(args, "--state", cfg.StatePath)
	}
	child := exec.Command(exe, args...)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = os.Environ()
	if cfg.Token != "" {
		child.Env = append(child.Env, "DISCLI_TOKEN="+cfg.Token)
	}
	if err := child.Start(); err != nil {
		return err
	}
	return waitForPing(cmd.Context(), cfg)
}

func waitForPing(ctx context.Context, cfg config.Config) error {
	cli := client.New(cfg.DaemonAddr, cfg.DaemonToken, cfg.Timeout)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(cfg.Timeout)
	defer timeout.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return errors.New("daemon did not respond before timeout")
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := cli.Ping(pingCtx)
			cancel()
			if err == nil {
				return nil
			}
		}
	}
}

func parseIntents(raw string) (discordgo.Intent, error) {
	if raw == "" {
		return discordgo.IntentsAllWithoutPrivileged, nil
	}
	var out discordgo.Intent
	for _, part := range splitCSV(raw) {
		switch part {
		case "guilds":
			out |= discordgo.IntentsGuilds
		case "guild_messages":
			out |= discordgo.IntentsGuildMessages
		case "dm_messages":
			out |= discordgo.IntentsDirectMessages
		case "message_content":
			out |= discordgo.IntentsMessageContent
		default:
			return 0, fmt.Errorf("unknown intent: %s", part)
		}
	}
	return out, nil
}

func splitCSV(raw string) []string {
	var parts []string
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		parts = append(parts, trimmed)
	}
	return parts
}

func generateToken(size int) (string, error) {
	if size <= 0 {
		size = 32
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}

func selectAttachment(atts []client.Attachment, attachmentID string, index int) (client.Attachment, error) {
	if len(atts) == 0 {
		return client.Attachment{}, errors.New("no attachments found")
	}
	if attachmentID != "" {
		for _, att := range atts {
			if att.ID == attachmentID {
				return att, nil
			}
		}
		return client.Attachment{}, fmt.Errorf("attachment %s not found", attachmentID)
	}
	if index >= 0 {
		if index >= len(atts) {
			return client.Attachment{}, fmt.Errorf("attachment index %d out of range", index)
		}
		return atts[index], nil
	}
	if len(atts) == 1 {
		return atts[0], nil
	}
	return client.Attachment{}, errors.New("multiple attachments found; select by --attachment-id or --index")
}

func downloadToFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	return nil
}

func output(cmd *cobra.Command, payload any, fallback string) error {
	jsonOut := cmd.Context().Value(jsonKey{}).(bool)
	if !jsonOut {
		fmt.Fprintln(cmd.OutOrStdout(), fallback)
		return nil
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func exitCode(_ error) int {
	return 1
}
