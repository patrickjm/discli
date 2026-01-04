package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type thresholdState struct {
	Thresholds map[string]string `json:"thresholds"`
}

type ThresholdStore struct {
	path       string
	mu         sync.RWMutex
	thresholds map[string]string
}

func NewThresholdStore(path string) (*ThresholdStore, error) {
	store := &ThresholdStore{
		path:       path,
		thresholds: map[string]string{},
	}
	if path == "" {
		return store, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, err
	}
	var state thresholdState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.Thresholds != nil {
		store.thresholds = state.Thresholds
	}
	return store, nil
}

func (s *ThresholdStore) Get(channelID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.thresholds[channelID]
}

func (s *ThresholdStore) Upsert(channelID, messageID string) error {
	if channelID == "" || messageID == "" {
		return errors.New("channel_id and message_id are required")
	}
	s.mu.Lock()
	s.thresholds[channelID] = messageID
	s.mu.Unlock()
	return s.persist()
}

func (s *ThresholdStore) persist() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	s.mu.RLock()
	state := thresholdState{Thresholds: map[string]string{}}
	for k, v := range s.thresholds {
		state.Thresholds[k] = v
	}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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

type PingStore struct {
	mu   sync.RWMutex
	list []Ping
	max  int
}

func NewPingStore(max int) *PingStore {
	if max <= 0 {
		max = 100
	}
	return &PingStore{max: max}
}

func (s *PingStore) Add(p Ping) {
	s.mu.Lock()
	s.list = append(s.list, p)
	if len(s.list) > s.max {
		s.list = s.list[len(s.list)-s.max:]
	}
	s.mu.Unlock()
}

func (s *PingStore) List(limit int) []Ping {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.list) {
		limit = len(s.list)
	}
	out := make([]Ping, 0, limit)
	for i := len(s.list) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.list[i])
	}
	return out
}

func (s *PingStore) Clear() {
	s.mu.Lock()
	s.list = nil
	s.mu.Unlock()
}
