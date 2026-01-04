package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
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

type MessagesResponse struct {
	Messages    []Message `json:"messages"`
	ThresholdID string    `json:"threshold_id,omitempty"`
	MaxID       string    `json:"max_id,omitempty"`
	MinID       string    `json:"min_id,omitempty"`
	UnreadOnly  bool      `json:"unread_only"`
}

func New(addr, token string, timeout time.Duration) *Client {
	transport := &http.Transport{}
	return &Client{
		httpClient: &http.Client{Timeout: timeout, Transport: transport},
		baseURL:    "http://" + addr,
		token:      token,
	}
}

func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/ping", nil)
	if err != nil {
		return err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon ping failed: %s", resp.Status)
	}
	return nil
}

func (c *Client) SendMessage(ctx context.Context, req SendRequest) (SendResponse, error) {
	var out SendResponse
	if req.ChannelID == "" || req.Content == "" {
		return out, fmt.Errorf("channel id and content are required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/send", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuth(httpReq)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("send failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) SendMessageWithFiles(ctx context.Context, req SendRequest, files []string) (SendResponse, error) {
	var out SendResponse
	if req.ChannelID == "" || (req.Content == "" && len(files) == 0) {
		return out, fmt.Errorf("channel id and content or file are required")
	}
	if len(files) == 0 {
		return c.SendMessage(ctx, req)
	}
	payload, contentType, err := buildMultipart(req.ChannelID, "", req.Content, req.MentionUserIDs, req.MentionRoleIDs, req.SuppressMentions, false, files)
	if err != nil {
		return out, err
	}
	reqURL := c.baseURL + "/v1/send"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, payload)
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", contentType)
	c.addAuth(httpReq)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("send failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) SendReply(ctx context.Context, req ReplyRequest) (ReplyResponse, error) {
	var out ReplyResponse
	if req.ChannelID == "" || req.MessageID == "" || req.Content == "" {
		return out, fmt.Errorf("channel id, message id, and content are required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/reply", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuth(httpReq)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("reply failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) SendReplyWithFiles(ctx context.Context, req ReplyRequest, files []string) (ReplyResponse, error) {
	var out ReplyResponse
	if req.ChannelID == "" || req.MessageID == "" || (req.Content == "" && len(files) == 0) {
		return out, fmt.Errorf("channel id, message id, and content or file are required")
	}
	if len(files) == 0 {
		return c.SendReply(ctx, req)
	}
	payload, contentType, err := buildMultipart(req.ChannelID, req.MessageID, req.Content, req.MentionUserIDs, req.MentionRoleIDs, req.SuppressMentions, req.FailIfNotExist, files)
	if err != nil {
		return out, err
	}
	reqURL := c.baseURL + "/v1/reply"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, payload)
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", contentType)
	c.addAuth(httpReq)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("reply failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) ReadMessages(ctx context.Context, channelID string, limit int, before string, unread bool, mark bool, withReplies bool) (MessagesResponse, error) {
	var out MessagesResponse
	if channelID == "" {
		return out, fmt.Errorf("channel id is required")
	}
	q := url.Values{}
	q.Set("channel_id", channelID)
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if before != "" {
		q.Set("before", before)
	}
	if !unread {
		q.Set("unread", "false")
	}
	if mark {
		q.Set("mark", "true")
	}
	if withReplies {
		q.Set("with_replies", "true")
	}
	endpoint := c.baseURL + "/v1/messages?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("read failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

type MessageResponse struct {
	Message Message `json:"message"`
}

func (c *Client) GetMessage(ctx context.Context, channelID, messageID string) (MessageResponse, error) {
	var out MessageResponse
	if channelID == "" || messageID == "" {
		return out, fmt.Errorf("channel id and message id are required")
	}
	q := url.Values{}
	q.Set("channel_id", channelID)
	q.Set("message_id", messageID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/message?"+q.Encode(), nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("message failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

type ThresholdResponse struct {
	ChannelID   string `json:"channel_id"`
	ThresholdID string `json:"threshold_id"`
}

func (c *Client) GetThreshold(ctx context.Context, channelID string) (ThresholdResponse, error) {
	var out ThresholdResponse
	if channelID == "" {
		return out, fmt.Errorf("channel id is required")
	}
	q := url.Values{}
	q.Set("channel_id", channelID)
	endpoint := c.baseURL + "/v1/thresholds?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("threshold read failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) UpsertThreshold(ctx context.Context, channelID, messageID string) (ThresholdResponse, error) {
	var out ThresholdResponse
	if channelID == "" || messageID == "" {
		return out, fmt.Errorf("channel id and message id are required")
	}
	body, err := json.Marshal(map[string]string{"channel_id": channelID, "message_id": messageID})
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/thresholds", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("threshold upsert failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

type Guild struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type GuildsResponse struct {
	Guilds []Guild `json:"guilds"`
}

func (c *Client) ListGuilds(ctx context.Context) (GuildsResponse, error) {
	var out GuildsResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/guilds", nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("guilds failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) GetGuild(ctx context.Context, guildID string) (map[string]any, error) {
	var out map[string]any
	if guildID == "" {
		return out, fmt.Errorf("guild id is required")
	}
	q := url.Values{}
	q.Set("guild_id", guildID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/guild?"+q.Encode(), nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("guild failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

type ChannelsResponse struct {
	Channels []map[string]any `json:"channels"`
}

func (c *Client) ListChannels(ctx context.Context, guildID string) (ChannelsResponse, error) {
	var out ChannelsResponse
	if guildID == "" {
		return out, fmt.Errorf("guild id is required")
	}
	q := url.Values{}
	q.Set("guild_id", guildID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/channels?"+q.Encode(), nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("channels failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) GetChannel(ctx context.Context, channelID string) (map[string]any, error) {
	var out map[string]any
	if channelID == "" {
		return out, fmt.Errorf("channel id is required")
	}
	q := url.Values{}
	q.Set("channel_id", channelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/channel?"+q.Encode(), nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("channel failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) GetUser(ctx context.Context, userID string) (map[string]any, error) {
	var out map[string]any
	if userID == "" {
		return out, fmt.Errorf("user id is required")
	}
	q := url.Values{}
	q.Set("user_id", userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/user?"+q.Encode(), nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("user failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

type PingsResponse struct {
	Pings []Ping `json:"pings"`
}

type Ping struct {
	MessageID string `json:"message_id"`
	ChannelID string `json:"channel_id"`
	GuildID   string `json:"guild_id"`
	AuthorID  string `json:"author_id"`
	Author    string `json:"author"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
}

func (c *Client) ListPings(ctx context.Context, limit int) (PingsResponse, error) {
	var out PingsResponse
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	endpoint := c.baseURL + "/v1/pings"
	if encoded := q.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("pings failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

type ResolvedPing struct {
	Ping
	GuildName   string `json:"guild_name,omitempty"`
	ChannelName string `json:"channel_name,omitempty"`
	Link        string `json:"link,omitempty"`
}

type PingsResolvedResponse struct {
	Pings []ResolvedPing `json:"pings"`
}

func (c *Client) ListPingsResolved(ctx context.Context, limit int) (PingsResolvedResponse, error) {
	var out PingsResolvedResponse
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	endpoint := c.baseURL + "/v1/pings/resolve"
	if encoded := q.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("pings resolve failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) ClearPings(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/pings/clear", nil)
	if err != nil {
		return err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pings clear failed: %s", resp.Status)
	}
	return nil
}

type Reaction struct {
	Emoji string `json:"emoji"`
	Count int    `json:"count"`
}

type ReactionsResponse struct {
	Reactions []Reaction `json:"reactions"`
}

func (c *Client) ListReactions(ctx context.Context, channelID, messageID string) (ReactionsResponse, error) {
	var out ReactionsResponse
	if channelID == "" || messageID == "" {
		return out, fmt.Errorf("channel id and message id are required")
	}
	q := url.Values{}
	q.Set("channel_id", channelID)
	q.Set("message_id", messageID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/reactions?"+q.Encode(), nil)
	if err != nil {
		return out, err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("reactions failed: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) AddReaction(ctx context.Context, channelID, messageID, emoji string) error {
	if channelID == "" || messageID == "" || emoji == "" {
		return fmt.Errorf("channel id, message id, and emoji are required")
	}
	body, err := json.Marshal(map[string]string{"channel_id": channelID, "message_id": messageID, "emoji": emoji})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/reactions/add", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reaction add failed: %s", resp.Status)
	}
	return nil
}

func (c *Client) RemoveReaction(ctx context.Context, channelID, messageID, emoji string) error {
	if channelID == "" || messageID == "" || emoji == "" {
		return fmt.Errorf("channel id, message id, and emoji are required")
	}
	body, err := json.Marshal(map[string]string{"channel_id": channelID, "message_id": messageID, "emoji": emoji})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/reactions/remove", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reaction remove failed: %s", resp.Status)
	}
	return nil
}

func buildMultipart(channelID, messageID, content string, mentionUsers, mentionRoles []string, suppressMentions bool, failIfMissing bool, files []string) (io.Reader, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("channel_id", channelID)
	if messageID != "" {
		_ = writer.WriteField("message_id", messageID)
	}
	_ = writer.WriteField("content", content)
	if suppressMentions {
		_ = writer.WriteField("suppress_mentions", "true")
	}
	if failIfMissing {
		_ = writer.WriteField("fail_if_not_exist", "true")
	}
	for _, id := range mentionUsers {
		if id == "" {
			continue
		}
		_ = writer.WriteField("mention_user_id", id)
	}
	for _, id := range mentionRoles {
		if id == "" {
			continue
		}
		_ = writer.WriteField("mention_role_id", id)
	}
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			_ = writer.Close()
			return nil, "", err
		}
		defer file.Close()
		part, err := writer.CreateFormFile("file", filepath.Base(path))
		if err != nil {
			_ = writer.Close()
			return nil, "", err
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = writer.Close()
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return &buf, writer.FormDataContentType(), nil
}

func (c *Client) Shutdown(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/shutdown", nil)
	if err != nil {
		return err
	}
	c.addAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("shutdown failed: %s", resp.Status)
	}
	return nil
}

func (c *Client) addAuth(req *http.Request) {
	if c.token == "" {
		return
	}
	req.Header.Set("X-Discli-Token", c.token)
}
