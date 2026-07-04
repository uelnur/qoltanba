package config

import (
	"strings"
	"testing"
)

func TestMQ_EnabledByConnectionValue(t *testing.T) {
	// Setting the URL/brokers enables the transport; nothing enables it otherwise.
	if load(t).Config.AnyMQEnabled() {
		t.Error("no MQ should be enabled by default")
	}
	l := load(t, "-amqp-url", "amqp://localhost", "-amqp-queue", "req")
	if !l.Config.AMQP.Enabled() || !l.Config.AnyMQEnabled() {
		t.Error("amqp should be enabled when url is set")
	}
	if l.Config.Kafka.Enabled() || l.Config.NATS.Enabled() {
		t.Error("only amqp should be enabled")
	}
}

func TestMQ_ValidationRequiresTargets(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"amqp needs queue", []string{"-amqp-url", "amqp://h"}, "amqp.queue is required"},
		{"kafka needs topic", []string{"-kafka-brokers", "h:9092", "-kafka-group", "g"}, "kafka.topic is required"},
		{"kafka needs group", []string{"-kafka-brokers", "h:9092", "-kafka-topic", "t", "-kafka-group", ""}, "kafka.group is required"},
		{"nats needs subject", []string{"-nats-url", "nats://h", "-nats-durable", "d"}, "nats.subject is required"},
		{"nats needs durable", []string{"-nats-url", "nats://h", "-nats-subject", "s", "-nats-durable", ""}, "nats.durable is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A library path is required in every mode; supply one so only the MQ
			// error under test surfaces.
			args := append([]string{"-lib-path", "/x/lib.so"}, tc.args...)
			err := load(t, args...).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMQ_ValidConfigPasses(t *testing.T) {
	l := load(t,
		"-lib-path", "/x/lib.so",
		"-amqp-url", "amqp://h", "-amqp-queue", "req",
		"-kafka-brokers", "h:9092", "-kafka-topic", "t", "-kafka-group", "g",
		"-nats-url", "nats://h", "-nats-subject", "s", "-nats-durable", "d",
	)
	if err := l.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestMQ_URLRedactedInDump(t *testing.T) {
	l := load(t, "-amqp-url", "amqp://user:secret@host", "-nats-url", "nats://user:secret@host")
	dump := l.Dump()
	if strings.Contains(dump, "secret") {
		t.Errorf("dump leaked a secret:\n%s", dump)
	}
	if !strings.Contains(dump, "amqp.url") || !strings.Contains(dump, "***") {
		t.Errorf("expected redacted amqp.url in dump:\n%s", dump)
	}
}
