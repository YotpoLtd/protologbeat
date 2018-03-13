package main

import (
	"testing"
	"time"

	"github.com/hartfordfive/protologbeat/config"
	"github.com/hartfordfive/protologbeat/protolog"

	"github.com/Graylog2/go-gelf/gelf"
	"github.com/stretchr/testify/assert"
	"github.com/elastic/beats/libbeat/beat"
)

func TestGreylogReceive(t *testing.T) {

	var logEntriesRecieved chan beat.Event
	var logEntriesErrors chan bool

	logEntriesRecieved = make(chan beat.Event, 1)
	logEntriesErrors = make(chan bool, 1)

	ll := protolog.NewLogListener(config.Config{EnableGelf: true, Port: 12000})

	go func(logs chan beat.Event, errs chan bool) {
		ll.Start(logs, errs)
	}(logEntriesRecieved, logEntriesErrors)

	var event beat.Event

	gw, err := gelf.NewWriter("127.0.0.1:12000")
	if err != nil {
		t.Errorf("NewWriter: %s", err)
		return
	}
	gw.CompressionType = gelf.CompressGzip

	expectedVersion := "1.1"
	expectedHost := "localhost"
	expectedShort := "This is a test message for protologbeat"
	expectedFull := "This is the full message expected for the test of gelf input."
	expectedTs := float64(time.Now().Unix())
	expectedLevel := int32(6)
	expectedLevelName := "Informational"
	expectedFacility := "local6"

	if err := gw.WriteMessage(&gelf.Message{
		Version:  expectedVersion,
		Host:     expectedHost,
		Short:    expectedShort,
		Full:     expectedFull,
		TimeUnix: expectedTs,
		Level:    expectedLevel,
		Facility: expectedFacility,
	}); err != nil {
		t.Errorf("Could not write message to GELF listener: %v", err)
		return
	}

	for {
		select {
		case <-logEntriesErrors:
			t.Errorf("Error receiving GELF format message")
			return
		case event = <-logEntriesRecieved:
			if event.Timestamp == time.Unix(0,0) {
				t.Errorf("Message missing timestamp field!: %v", event)
				return
			}
			assert.Equal(t, expectedVersion, event.Fields["gelf"].(map[string]interface{})["version"], "Version should be the same")
			assert.Equal(t, expectedHost, event.Fields["host"], "Host should be the same")
			assert.Equal(t, expectedShort, event.Fields["short_message"], "Short message should be the same")
			assert.Equal(t, expectedFull, event.Fields["full_message"], "Full message should be the same")
			assert.Equal(t, expectedLevelName, event.Fields["level"], "Level should be the same")
			assert.Equal(t, expectedFacility, event.Fields["facility"], "Facility should be the same")
			return
		}
	}
}
