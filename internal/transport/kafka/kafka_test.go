package kafka

import (
	"testing"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestReplyTopicFor(t *testing.T) {
	c := &Consumer{cfg: Config{ReplyTopic: "default-replies"}}

	if got := c.replyTopicFor(&kgo.Record{}); got != "default-replies" {
		t.Errorf("no header: got %q, want configured default", got)
	}

	withHeader := &kgo.Record{Headers: []kgo.RecordHeader{{Key: replyTopicHeader, Value: []byte("per-msg")}}}
	if got := c.replyTopicFor(withHeader); got != "per-msg" {
		t.Errorf("header override: got %q, want per-msg", got)
	}

	empty := &kgo.Record{Headers: []kgo.RecordHeader{{Key: replyTopicHeader, Value: []byte("")}}}
	if got := c.replyTopicFor(empty); got != "default-replies" {
		t.Errorf("empty header ignored: got %q, want default", got)
	}

	noDefault := &Consumer{cfg: Config{}}
	if got := noDefault.replyTopicFor(&kgo.Record{}); got != "" {
		t.Errorf("fire-and-forget: got %q, want empty", got)
	}
}
