package beater

import (
	"fmt"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/hartfordfive/protologbeat/config"
	"github.com/hartfordfive/protologbeat/protolog"
)

var log *logp.Logger

func init() {
	log = logp.NewLogger("protologbeat")
}

type Protologbeat struct {
	done        chan struct{}
	config      config.Config
	client      beat.Client
	logListener *protolog.LogListener
}

// Creates beater
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	conf := config.DefaultConfig
	if err := cfg.Unpack(conf); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Protologbeat{
		done:        make(chan struct{}),
		config:      conf,
		logListener: protolog.NewLogListener(conf),
	}

	return bt, nil
}

func (bt *Protologbeat) Run(b *beat.Beat) error {
	var err error
	bt.client, err = b.Publisher.Connect()

	if err != nil {
		return err
	}
	log.Info("protologbeat is running! Hit CTRL-C to stop it.")
	logEntriesRecieved := make(chan beat.Event, 100000)
	logEntriesErrors := make(chan bool, 1)

	go func(logs chan beat.Event, errs chan bool) {
		bt.logListener.Start(logs, errs)
	}(logEntriesRecieved, logEntriesErrors)

	var event beat.Event

	for {
		select {
		case <-bt.done:
			return nil
		case <-logEntriesErrors:
			return nil
		case event = <-logEntriesRecieved:
			if event.Fields == nil {
				return nil
			}
			bt.client.Publish(event)
			log.Info("Event sent")
		}
	}

}

func (bt *Protologbeat) Stop() {
	bt.client.Close()
	close(bt.done)
	bt.logListener.Shutdown()
}
