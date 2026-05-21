package slack

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// Options contains necessary options required for Slack communication
type Options struct {
	// WebhookURL is the URL of the Slack incoming webhook
	WebhookURL string `yaml:"webhook-url" validate:"required"`
	// Channel is the Slack channel to post to (optional, overrides webhook default)
	Channel string `yaml:"channel"`
	// Username is the username to post as (optional)
	Username string `yaml:"username"`

	HttpClient  *http.Client `yaml:"-"`
	ExecutionId string       `yaml:"-"`
}

// Exporter type for Slack
type Exporter struct {
	options *Options
	client  *http.Client
}

// New creates and returns a new exporter for Slack
func New(option *Options) (*Exporter, error) {
	if option.WebhookURL == "" {
		return nil, errors.New("slack webhook URL is required")
	}

	client := option.HttpClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &Exporter{
		options: option,
		client:  client,
	}, nil
}

// slackPayload represents the JSON payload sent to Slack
type slackPayload struct {
	Channel  string       `json:"channel,omitempty"`
	Username string       `json:"username,omitempty"`
	Blocks   []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Fields   []slackText `json:"fields,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Export exports a passed result event to Slack
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	payload := exporter.buildPayload(event)

	b, err := json.Marshal(&payload)
	if err != nil {
		return errors.Wrap(err, "could not marshal slack payload")
	}

	req, err := http.NewRequest(http.MethodPost, exporter.options.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := exporter.client.Do(req)
	if err != nil {
		return errors.Wrap(err, "could not send slack notification")
	}
	defer func() {
		_ = res.Body.Close()
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "could not read slack response")
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("slack responded with status %d: %s", res.StatusCode, string(body))
	}
	return nil
}

func (exporter *Exporter) buildPayload(event *output.ResultEvent) slackPayload {
	severity := strings.ToUpper(event.Info.SeverityHolder.Severity.String())
	severityEmoji := severityToEmoji(severity)

	header := slackBlock{
		Type: "header",
		Text: &slackText{
			Type: "plain_text",
			Text: fmt.Sprintf("%s [%s] %s", severityEmoji, severity, event.Info.Name),
		},
	}

	var fields []slackText
	fields = append(fields, slackText{
		Type: "mrkdwn",
		Text: fmt.Sprintf("*Template:*\n%s", event.TemplateID),
	})
	fields = append(fields, slackText{
		Type: "mrkdwn",
		Text: fmt.Sprintf("*Host:*\n%s", event.Host),
	})
	if event.Matched != "" {
		fields = append(fields, slackText{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Matched:*\n%s", event.Matched),
		})
	}
	if event.IP != "" {
		fields = append(fields, slackText{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*IP:*\n%s", event.IP),
		})
	}

	section := slackBlock{
		Type:   "section",
		Fields: fields,
	}

	blocks := []slackBlock{header, section}

	if event.Info.Description != "" {
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Description:*\n%s", event.Info.Description),
			},
		})
	}

	if len(event.ExtractedResults) > 0 {
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Extracted Results:*\n```%s```", strings.Join(event.ExtractedResults, "\n")),
			},
		})
	}

	blocks = append(blocks, slackBlock{
		Type: "context",
		Elements: []slackText{
			{
				Type: "mrkdwn",
				Text: fmt.Sprintf("Nuclei scan at %s", time.Now().Format(time.RFC3339)),
			},
		},
	})

	payload := slackPayload{
		Blocks: blocks,
	}
	if exporter.options.Channel != "" {
		payload.Channel = exporter.options.Channel
	}
	if exporter.options.Username != "" {
		payload.Username = exporter.options.Username
	}
	return payload
}

func severityToEmoji(severity string) string {
	switch severity {
	case "CRITICAL":
		return "\xf0\x9f\x94\xb4" // red circle
	case "HIGH":
		return "\xf0\x9f\x9f\xa0" // orange circle
	case "MEDIUM":
		return "\xf0\x9f\x9f\xa1" // yellow circle
	case "LOW":
		return "\xf0\x9f\x94\xb5" // blue circle
	case "INFO":
		return "\xe2\xac\x9c" // white circle
	default:
		return "\xe2\x9a\xaa" // white circle
	}
}

// Close closes the exporter after operation
func (exporter *Exporter) Close() error {
	return nil
}
