package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

type Server struct {
	session    *discordgo.Session
	server     *http.Server
	authToken  string
	shutdownCh chan struct{}
	thresholds *ThresholdStore
	pings      *PingStore
	botUserID  string
}

type SendRequest struct {
	ChannelID        string   `json:"channel_id"`
	Content          string   `json:"content"`
	MentionUserIDs   []string `json:"mention_user_ids,omitempty"`
	MentionRoleIDs   []string `json:"mention_role_ids,omitempty"`
	SuppressMentions bool     `json:"suppress_mentions,omitempty"`
}

type Message struct {
	ID          string       `json:"id"`
	ChannelID   string       `json:"channel_id"`
	Author      string       `json:"author"`
	Content     string       `json:"content"`
	Timestamp   string       `json:"timestamp"`
	ReplyToID   string       `json:"reply_to_id,omitempty"`
	ReplyFrom   string       `json:"reply_from,omitempty"`
	ReplyText   string       `json:"reply_text,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

type SendResponse struct {
	Message Message `json:"message"`
}

type ReplyRequest struct {
	ChannelID        string   `json:"channel_id"`
	MessageID        string   `json:"message_id"`
	Content          string   `json:"content"`
	FailIfNotExist   bool     `json:"fail_if_not_exist"`
	MentionUserIDs   []string `json:"mention_user_ids,omitempty"`
	MentionRoleIDs   []string `json:"mention_role_ids,omitempty"`
	SuppressMentions bool     `json:"suppress_mentions,omitempty"`
}

type ReplyResponse struct {
	Message Message `json:"message"`
}

type Attachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	URL         string `json:"url"`
	Size        int    `json:"size"`
	ContentType string `json:"content_type,omitempty"`
}

type MessageResponse struct {
	Message Message `json:"message"`
}

type MessagesResponse struct {
	Messages    []Message `json:"messages"`
	ThresholdID string    `json:"threshold_id,omitempty"`
	MaxID       string    `json:"max_id,omitempty"`
	MinID       string    `json:"min_id,omitempty"`
	UnreadOnly  bool      `json:"unread_only"`
}

func Run(ctx context.Context, token, addr, authToken, statePath string, intents discordgo.Intent) error {
	if token == "" {
		return errors.New("discord token is required")
	}
	if addr == "" {
		return errors.New("daemon address is required")
	}
	session, err := discordgo.New(withBotPrefix(token))
	if err != nil {
		return err
	}
	session.Identify.Intents = intents
	if err := session.Open(); err != nil {
		return err
	}
	defer session.Close()

	botUserID := ""
	if session.State != nil && session.State.User != nil {
		botUserID = session.State.User.ID
	}
	if botUserID == "" {
		if user, uerr := session.User("@me"); uerr == nil && user != nil {
			botUserID = user.ID
		}
	}

	thresholds, err := NewThresholdStore(statePath)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	mux := http.NewServeMux()
	srv := &Server{
		session:    session,
		authToken:  authToken,
		shutdownCh: make(chan struct{}),
		thresholds: thresholds,
		pings:      NewPingStore(200),
		botUserID:  botUserID,
	}
	mux.HandleFunc("/v1/ping", srv.authorized(srv.handlePing))
	mux.HandleFunc("/v1/send", srv.authorized(srv.handleSend))
	mux.HandleFunc("/v1/reply", srv.authorized(srv.handleReply))
	mux.HandleFunc("/v1/messages", srv.authorized(srv.handleMessages))
	mux.HandleFunc("/v1/message", srv.authorized(srv.handleMessage))
	mux.HandleFunc("/v1/reactions", srv.authorized(srv.handleReactions))
	mux.HandleFunc("/v1/reactions/add", srv.authorized(srv.handleReactionAdd))
	mux.HandleFunc("/v1/reactions/remove", srv.authorized(srv.handleReactionRemove))
	mux.HandleFunc("/v1/shutdown", srv.authorized(srv.handleShutdown))
	mux.HandleFunc("/v1/thresholds", srv.authorized(srv.handleThresholds))
	mux.HandleFunc("/v1/guilds", srv.authorized(srv.handleGuilds))
	mux.HandleFunc("/v1/guild", srv.authorized(srv.handleGuild))
	mux.HandleFunc("/v1/channels", srv.authorized(srv.handleChannels))
	mux.HandleFunc("/v1/channel", srv.authorized(srv.handleChannel))
	mux.HandleFunc("/v1/user", srv.authorized(srv.handleUser))
	mux.HandleFunc("/v1/pings", srv.authorized(srv.handlePings))
	mux.HandleFunc("/v1/pings/resolve", srv.authorized(srv.handlePingsResolve))
	mux.HandleFunc("/v1/pings/clear", srv.authorized(srv.handlePingsClear))
	server := &http.Server{Handler: mux}
	srv.server = server

	session.AddHandler(srv.handleMessageCreate)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return nil
	case <-srv.shutdownCh:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	req, files, err := parseSendRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ChannelID == "" || (req.Content == "" && len(files) == 0) {
		writeError(w, http.StatusBadRequest, "channel_id and content or file are required")
		return
	}
	content, allowed := applyMentions(req.Content, req.MentionUserIDs, req.MentionRoleIDs, req.SuppressMentions)
	msgSend := &discordgo.MessageSend{
		Content:         content,
		Files:           files,
		AllowedMentions: allowed,
	}
	msg, err := s.session.ChannelMessageSendComplex(req.ChannelID, msgSend)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := SendResponse{Message: fromDiscordMessage(msg)}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleReply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	req, files, err := parseReplyRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ChannelID == "" || req.MessageID == "" || (req.Content == "" && len(files) == 0) {
		writeError(w, http.StatusBadRequest, "channel_id, message_id, and content or file are required")
		return
	}
	if req.FailIfNotExist {
		if _, err := s.session.ChannelMessage(req.ChannelID, req.MessageID); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	content, allowed := applyMentions(req.Content, req.MentionUserIDs, req.MentionRoleIDs, req.SuppressMentions)
	msgSend := &discordgo.MessageSend{
		Content:         content,
		Files:           files,
		AllowedMentions: allowed,
		Reference: &discordgo.MessageReference{
			MessageID: req.MessageID,
			ChannelID: req.ChannelID,
		},
	}
	msg, err := s.session.ChannelMessageSendComplex(req.ChannelID, msgSend)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := ReplyResponse{Message: fromDiscordMessage(msg)}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	channelID := r.URL.Query().Get("channel_id")
	if channelID == "" {
		writeError(w, http.StatusBadRequest, "channel_id is required")
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
		if limit <= 0 || limit > 100 {
			limit = 20
		}
	}
	before := r.URL.Query().Get("before")
	unread := true
	if v := r.URL.Query().Get("unread"); v != "" {
		unread = v != "false"
	}
	mark := r.URL.Query().Get("mark") == "true"
	withReplies := r.URL.Query().Get("with_replies") == "true"
	msgs, err := s.session.ChannelMessages(channelID, limit, before, "", "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	thresholdID := s.thresholds.Get(channelID)
	resp := MessagesResponse{
		Messages:    make([]Message, 0, len(msgs)),
		ThresholdID: thresholdID,
		UnreadOnly:  unread,
	}
	var maxID, minID string
	for _, msg := range msgs {
		if unread && thresholdID != "" && !isNewer(msg.ID, thresholdID) {
			continue
		}
		out := fromDiscordMessage(msg)
		if withReplies && out.ReplyToID != "" && out.ReplyText == "" {
			if ref, err := s.session.ChannelMessage(channelID, out.ReplyToID); err == nil && ref != nil {
				if ref.Author != nil {
					out.ReplyFrom = ref.Author.Username
				}
				out.ReplyText = ref.Content
			}
		}
		resp.Messages = append(resp.Messages, out)
		maxID = maxSnowflake(maxID, msg.ID)
		minID = minSnowflake(minID, msg.ID)
	}
	resp.MaxID = maxID
	resp.MinID = minID
	if mark && unread && before == "" && maxID != "" {
		_ = s.thresholds.Upsert(channelID, maxID)
		resp.ThresholdID = maxID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	channelID := r.URL.Query().Get("channel_id")
	messageID := r.URL.Query().Get("message_id")
	if channelID == "" || messageID == "" {
		writeError(w, http.StatusBadRequest, "channel_id and message_id are required")
		return
	}
	msg, err := s.session.ChannelMessage(channelID, messageID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, MessageResponse{Message: fromDiscordMessage(msg)})
}

func (s *Server) handleReactions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	channelID := r.URL.Query().Get("channel_id")
	messageID := r.URL.Query().Get("message_id")
	if channelID == "" || messageID == "" {
		writeError(w, http.StatusBadRequest, "channel_id and message_id are required")
		return
	}
	msg, err := s.session.ChannelMessage(channelID, messageID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	type reaction struct {
		Emoji string `json:"emoji"`
		Count int    `json:"count"`
	}
	reactions := make([]reaction, 0, len(msg.Reactions))
	for _, react := range msg.Reactions {
		if react == nil || react.Emoji == nil {
			continue
		}
		reactions = append(reactions, reaction{
			Emoji: formatEmoji(react.Emoji),
			Count: react.Count,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"reactions": reactions})
}

func (s *Server) handleReactionAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		ChannelID string `json:"channel_id"`
		MessageID string `json:"message_id"`
		Emoji     string `json:"emoji"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.ChannelID == "" || req.MessageID == "" || req.Emoji == "" {
		writeError(w, http.StatusBadRequest, "channel_id, message_id, and emoji are required")
		return
	}
	if err := s.session.MessageReactionAdd(req.ChannelID, req.MessageID, req.Emoji); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReactionRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		ChannelID string `json:"channel_id"`
		MessageID string `json:"message_id"`
		Emoji     string `json:"emoji"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.ChannelID == "" || req.MessageID == "" || req.Emoji == "" {
		writeError(w, http.StatusBadRequest, "channel_id, message_id, and emoji are required")
		return
	}
	if err := s.session.MessageReactionRemove(req.ChannelID, req.MessageID, req.Emoji, "@me"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	select {
	case s.shutdownCh <- struct{}{}:
	default:
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "shutting_down"})
}

func (s *Server) handleThresholds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		channelID := r.URL.Query().Get("channel_id")
		if channelID == "" {
			writeError(w, http.StatusBadRequest, "channel_id is required")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"channel_id": channelID, "threshold_id": s.thresholds.Get(channelID)})
	case http.MethodPost:
		var req struct {
			ChannelID string `json:"channel_id"`
			MessageID string `json:"message_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if err := s.thresholds.Upsert(req.ChannelID, req.MessageID); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"channel_id": req.ChannelID, "threshold_id": req.MessageID})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleGuilds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	type guild struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	guilds := make([]guild, 0)
	if s.session.State != nil {
		for _, g := range s.session.State.Guilds {
			guilds = append(guilds, guild{ID: g.ID, Name: g.Name})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"guilds": guilds})
}

func (s *Server) handleGuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	guildID := r.URL.Query().Get("guild_id")
	if guildID == "" {
		writeError(w, http.StatusBadRequest, "guild_id is required")
		return
	}
	guild, err := s.session.Guild(guildID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, guild)
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	guildID := r.URL.Query().Get("guild_id")
	if guildID == "" {
		writeError(w, http.StatusBadRequest, "guild_id is required")
		return
	}
	channels, err := s.session.GuildChannels(guildID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

func (s *Server) handleChannel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	channelID := r.URL.Query().Get("channel_id")
	if channelID == "" {
		writeError(w, http.StatusBadRequest, "channel_id is required")
		return
	}
	channel, err := s.session.Channel(channelID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, channel)
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	user, err := s.session.User(userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handlePings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
		if limit <= 0 || limit > 200 {
			limit = 20
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"pings": s.pings.List(limit)})
}

func (s *Server) handlePingsResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
		if limit <= 0 || limit > 200 {
			limit = 20
		}
	}
	type resolvedPing struct {
		Ping
		GuildName   string `json:"guild_name,omitempty"`
		ChannelName string `json:"channel_name,omitempty"`
		Link        string `json:"link,omitempty"`
	}
	pings := s.pings.List(limit)
	out := make([]resolvedPing, 0, len(pings))
	for _, ping := range pings {
		entry := resolvedPing{Ping: ping}
		if ping.GuildID != "" {
			if g, err := s.session.Guild(ping.GuildID); err == nil && g != nil {
				entry.GuildName = g.Name
			}
		}
		if ping.ChannelID != "" {
			if ch, err := s.session.Channel(ping.ChannelID); err == nil && ch != nil {
				entry.ChannelName = ch.Name
			}
		}
		if ping.GuildID != "" && ping.ChannelID != "" && ping.MessageID != "" {
			entry.Link = "https://discord.com/channels/" + ping.GuildID + "/" + ping.ChannelID + "/" + ping.MessageID
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"pings": out})
}

func (s *Server) handlePingsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.pings.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (s *Server) handleMessageCreate(_ *discordgo.Session, msg *discordgo.MessageCreate) {
	if msg == nil || msg.Message == nil || s.botUserID == "" {
		return
	}
	if msg.Author != nil && msg.Author.ID == s.botUserID {
		return
	}
	for _, mention := range msg.Mentions {
		if mention != nil && mention.ID == s.botUserID {
			s.pings.Add(Ping{
				MessageID: msg.ID,
				ChannelID: msg.ChannelID,
				GuildID:   msg.GuildID,
				AuthorID:  msg.Author.ID,
				Author:    msg.Author.Username,
				Content:   msg.Content,
				Timestamp: msg.Timestamp.String(),
			})
			return
		}
	}
}

func (s *Server) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken != "" {
			if r.Header.Get("X-Discli-Token") != s.authToken {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		next(w, r)
	}
}

func fromDiscordMessage(msg *discordgo.Message) Message {
	author := ""
	if msg.Author != nil {
		author = msg.Author.Username
	}
	out := Message{
		ID:        msg.ID,
		ChannelID: msg.ChannelID,
		Author:    author,
		Content:   msg.Content,
		Timestamp: msg.Timestamp.String(),
	}
	if len(msg.Attachments) > 0 {
		out.Attachments = make([]Attachment, 0, len(msg.Attachments))
		for _, att := range msg.Attachments {
			out.Attachments = append(out.Attachments, Attachment{
				ID:          att.ID,
				Filename:    att.Filename,
				URL:         att.URL,
				Size:        att.Size,
				ContentType: att.ContentType,
			})
		}
	}
	if msg.ReferencedMessage != nil {
		out.ReplyToID = msg.ReferencedMessage.ID
		if msg.ReferencedMessage.Author != nil {
			out.ReplyFrom = msg.ReferencedMessage.Author.Username
		}
		out.ReplyText = msg.ReferencedMessage.Content
	} else if msg.MessageReference != nil {
		out.ReplyToID = msg.MessageReference.MessageID
	}
	return out
}

func parseSendRequest(r *http.Request) (SendRequest, []*discordgo.File, error) {
	if isMultipart(r) {
		req, files, err := parseMultipartSend(r, false)
		if err != nil {
			return SendRequest{}, nil, err
		}
		return SendRequest{
			ChannelID:        req.ChannelID,
			Content:          req.Content,
			MentionUserIDs:   req.MentionUserIDs,
			MentionRoleIDs:   req.MentionRoleIDs,
			SuppressMentions: req.SuppressMentions,
		}, files, nil
	}
	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, nil, err
	}
	return req, nil, nil
}

func parseReplyRequest(r *http.Request) (ReplyRequest, []*discordgo.File, error) {
	if isMultipart(r) {
		req, files, err := parseMultipartSend(r, true)
		if err != nil {
			return ReplyRequest{}, nil, err
		}
		return ReplyRequest{
			ChannelID:        req.ChannelID,
			MessageID:        req.MessageID,
			Content:          req.Content,
			FailIfNotExist:   req.FailIfNotExist,
			MentionUserIDs:   req.MentionUserIDs,
			MentionRoleIDs:   req.MentionRoleIDs,
			SuppressMentions: req.SuppressMentions,
		}, files, nil
	}
	var req ReplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, nil, err
	}
	return req, nil, nil
}

type multipartSend struct {
	ChannelID        string
	MessageID        string
	Content          string
	FailIfNotExist   bool
	MentionUserIDs   []string
	MentionRoleIDs   []string
	SuppressMentions bool
}

func parseMultipartSend(r *http.Request, includeReply bool) (multipartSend, []*discordgo.File, error) {
	var req multipartSend
	if err := r.ParseMultipartForm(25 << 20); err != nil {
		return req, nil, err
	}
	form := r.MultipartForm
	if form == nil {
		return req, nil, errors.New("missing multipart form")
	}
	req.ChannelID = formValue(form, "channel_id")
	req.Content = formValue(form, "content")
	req.MentionUserIDs = form.Value["mention_user_id"]
	req.MentionRoleIDs = form.Value["mention_role_id"]
	req.SuppressMentions = parseBool(formValue(form, "suppress_mentions"))
	if includeReply {
		req.MessageID = formValue(form, "message_id")
		req.FailIfNotExist = parseBool(formValue(form, "fail_if_not_exist"))
	}
	files := make([]*discordgo.File, 0)
	for _, header := range form.File["file"] {
		file, err := header.Open()
		if err != nil {
			return req, nil, err
		}
		data, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil {
			return req, nil, err
		}
		files = append(files, &discordgo.File{
			Name:        header.Filename,
			ContentType: header.Header.Get("Content-Type"),
			Reader:      bytes.NewReader(data),
		})
	}
	return req, files, nil
}

func formValue(form *multipart.Form, key string) string {
	if form == nil {
		return ""
	}
	if values, ok := form.Value[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func isMultipart(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data")
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func applyMentions(content string, userIDs, roleIDs []string, suppress bool) (string, *discordgo.MessageAllowedMentions) {
	if suppress {
		return content, &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}
	}
	if len(userIDs) == 0 && len(roleIDs) == 0 {
		return content, nil
	}
	content = appendMentions(content, userIDs, roleIDs)
	return content, &discordgo.MessageAllowedMentions{
		Users: userIDs,
		Roles: roleIDs,
		Parse: []discordgo.AllowedMentionType{},
	}
}

func appendMentions(content string, userIDs, roleIDs []string) string {
	builder := strings.Builder{}
	builder.WriteString(content)
	for _, id := range userIDs {
		if id == "" {
			continue
		}
		builder.WriteString(" <@")
		builder.WriteString(id)
		builder.WriteString(">")
	}
	for _, id := range roleIDs {
		if id == "" {
			continue
		}
		builder.WriteString(" <@&")
		builder.WriteString(id)
		builder.WriteString(">")
	}
	return builder.String()
}

func formatEmoji(emoji *discordgo.Emoji) string {
	if emoji == nil {
		return ""
	}
	if emoji.ID != "" {
		return emoji.Name + ":" + emoji.ID
	}
	return emoji.Name
}

func isNewer(candidate, threshold string) bool {
	if threshold == "" {
		return true
	}
	candidateNum, err := strconv.ParseUint(candidate, 10, 64)
	if err != nil {
		return true
	}
	thresholdNum, err := strconv.ParseUint(threshold, 10, 64)
	if err != nil {
		return true
	}
	return candidateNum > thresholdNum
}

func maxSnowflake(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if isNewer(a, b) {
		return a
	}
	return b
}

func minSnowflake(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if isNewer(a, b) {
		return b
	}
	return a
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func withBotPrefix(token string) string {
	trimmed := strings.TrimSpace(token)
	if strings.HasPrefix(trimmed, "Bot ") {
		return trimmed
	}
	return "Bot " + trimmed
}
