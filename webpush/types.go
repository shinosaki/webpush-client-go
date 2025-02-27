package webpush

import "encoding/json"

// https://developer.mozilla.org/docs/Web/API/Notification
type WebPushPayload struct {
	Title string          `json:"title"`
	Body  string          `json:"body"`
	Icon  string          `json:"icon"` // icon url
	Data  json.RawMessage `json:"data"` // custom data field
}
