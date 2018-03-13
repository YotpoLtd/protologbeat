package protolog

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/Graylog2/go-gelf/gelf"
	"github.com/hartfordfive/protologbeat/config"
	"github.com/pquerna/ffjson/ffjson"
	"github.com/xeipuuv/gojsonschema"
	"github.com/elastic/beats/libbeat/beat"
)

type LogListener struct {
	config             config.Config
	jsonSchema         map[string]gojsonschema.JSONLoader
	logEntriesRecieved chan beat.Event
	logEntriesError    chan bool
}

var gelfLevels = map[int32]string{
	0: "Emergency",
	1: "Alert",
	2: "Critical",
	3: "Error",
	4: "Warning",
	5: "Notice",
	6: "Informational",
	7: "Debug",
}

var log *logp.Logger

func init() {
	log = logp.NewLogger("loglistener")
}

func NewLogListener(cfg config.Config) *LogListener {
	ll := &LogListener{
		config: cfg,
	}
	if !ll.config.EnableGelf && ll.config.EnableJsonValidation {
		ll.jsonSchema = map[string]gojsonschema.JSONLoader{}
		for name, path := range ll.config.JsonSchema {
			log.Infof("Loading JSON schema %s from %s", name, path)
			schemaLoader := gojsonschema.NewReferenceLoader("file://" + path)
			ds := schemaLoader
			ll.jsonSchema[name] = ds
		}
	}
	return ll
}

func (ll *LogListener) Start(logEntriesRecieved chan beat.Event, logEntriesError chan bool) {

	ll.logEntriesRecieved = logEntriesRecieved
	ll.logEntriesError = logEntriesError

	address := fmt.Sprintf("%s:%d", ll.config.Address, ll.config.Port)

	if ll.config.Protocol == "tcp" {
		ll.startTCP(ll.config.Protocol, address)
	} else if ll.config.EnableGelf {
		ll.startGELF(address)
	} else {
		ll.startUDP(ll.config.Protocol, address)
	}

}

func (ll *LogListener) startTCP(proto string, address string) {

	l, err := net.Listen(proto, address)

	if err != nil {
		log.Errorf("Error listening on % socket via %s: %v", ll.config.Protocol, address, err.Error())
		ll.logEntriesError <- true
		return
	}
	defer l.Close()

	log.Infof("Now listening for logs via %s on %s", ll.config.Protocol, address)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Errorf("Error accepting log event: %v", err.Error())
			continue
		}

		buffer := make([]byte, ll.config.MaxMsgSize)

		length, err := conn.Read(buffer)
		if err != nil {
			e, ok := err.(net.Error)
			if ok && e.Timeout() {
				log.Errorf("Timeout reading from socket: %v", err)
				ll.logEntriesError <- true
				return
			}
		}
		go ll.processMessage(strings.TrimSpace(string(buffer[:length])))

	}
}

func (ll *LogListener) startUDP(proto string, address string) {
	l, err := net.ListenPacket(proto, address)

	if err != nil {
		log.Errorf("Error listening on % socket via %s: %v", ll.config.Protocol, address, err.Error())
		ll.logEntriesError <- true
		return
	}
	defer l.Close()

	log.Infof("Now listening for logs via %s on %s", ll.config.Protocol, address)

	for {
		buffer := make([]byte, ll.config.MaxMsgSize)
		length, _, err := l.ReadFrom(buffer)
		if err != nil {
			log.Errorf("Error reading from buffer: %v", err.Error())
			continue
		}
		if length == 0 {
			return
		}
		go ll.processMessage(strings.TrimSpace(string(buffer[:length])))
	}
}

func (ll *LogListener) startGELF(address string) {

	gr, err := gelf.NewReader(address)
	if err != nil {
		log.Errorf("Error starting GELF listener on %s: %v", address, err.Error())
		ll.logEntriesError <- true
	}

	log.Infof("Listening for GELF encoded messages on %s...", address)

	for {
		msg, err := gr.ReadMessage()
		if err != nil {
			log.Errorf("Could not read GELF message: %v", err)
		} else {
			go ll.processGelfMessage(msg)
		}
	}

}

func (ll *LogListener) Shutdown() {
	close(ll.logEntriesError)
	close(ll.logEntriesRecieved)
}

func (ll *LogListener) processMessage(logData string) {

	if logData == "" {
		log.Error("Event is empty")
		return
	}
	event := beat.Event{
		Fields: common.MapStr{},
		Meta: common.MapStr{},
		Timestamp: time.Now(),
	}

	if ll.config.EnableSyslogFormatOnly {
		msg, facility, severity, err := GetSyslogMsgDetails(logData)
		if err == nil {
			event.Fields["facility"] = facility
			event.Fields["severity"] = severity
			event.Fields["message"] = msg
		}
	} else if ll.config.JsonMode {
		if ll.config.MergeFieldsToRoot {
			if err := ffjson.Unmarshal([]byte(logData), &event.Fields); err != nil {
				log.Errorf("Could not parse JSON: %v", err)
				event.Fields["message"] = logData
				event.Fields["tags"] = []string{"_protologbeat_json_parse_failure"}
				goto PreSend
			}
		} else {
			nestedData := common.MapStr{}
			if err := ffjson.Unmarshal([]byte(logData), &nestedData); err != nil {
				log.Errorf("Could not parse JSON: %v", err)
				event.Fields["message"] = logData
				event.Fields["tags"] = []string{"_protologbeat_json_parse_failure"}
				goto PreSend
			} else {
				event.Fields["log"] = nestedData
			}
		}

		schemaSet := false
		hasType := false
		if _, ok := event.Fields["type"]; ok {
			hasType = true
		}

		if hasType {
			_, schemaSet = ll.jsonSchema[event.Fields["type"].(string)]
		}

		if ll.config.ValidateAllJSONTypes && !schemaSet {
			if ll.config.Debug && hasType {
				log.Errorf("Log entry of type '%s' has no JSON schema set.", event.Fields["type"].(string))
			} else if ll.config.Debug {
				log.Error("Log entry has no type.")
			}
			return
		}

		if ll.config.EnableJsonValidation && schemaSet {

			result, err := gojsonschema.Validate(ll.jsonSchema[event.Fields["type"].(string)], gojsonschema.NewStringLoader(logData))
			if err != nil {
				if ll.config.Debug {
					log.Errorf("Error with JSON object: %s", err.Error())
				}
				return
			}

			if !result.Valid() {
				if ll.config.Debug {
					log.Errorf("Log entry does not match specified schema for type '%s'. (Note: ensure you have 'type' field (string) at the root level in your schema)", event.Fields["type"].(string))
				}
				return
			}
		}

	} else {
		event.Fields["message"] = logData
	}

PreSend:
	ll.logEntriesRecieved <- event
}

func (ll *LogListener) processGelfMessage(msg *gelf.Message) {

	event := beat.Event{}
	fields := common.MapStr{}
	fields["gelf"] = map[string]interface{}{"version": msg.Version}
	fields["host"] = msg.Host
	fields["short_message"] = msg.Short
	fields["full_message"] = msg.Full

	for name, value := range msg.Extra {
		fields[name] = value
	}

	// 1 ms = 1000000 ns
	if msg.TimeUnix == 0 {
		event.Timestamp = time.Now()
	} else {
		millisec := msg.TimeUnix - float64(int64(msg.TimeUnix))
		ms := fmt.Sprintf("%.4f", millisec)
		msf, err := strconv.ParseFloat(ms, 64)
		if err != nil {
			event.Timestamp = time.Now()
		} else {
			event.Timestamp = time.Unix(int64(msg.TimeUnix), int64(msf)*1000000)
		}
	}

	// Parse level to  be human readable

	fields["level"] = gelfLevels[msg.Level]
	fields["facility"] = msg.Facility
	event.Fields = fields
	ll.logEntriesRecieved <- event

}
