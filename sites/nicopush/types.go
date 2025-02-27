package nicopush

import "time"

type (
	DestApp string
)

const (
	NICO_ACCOUNT_WEBPUSH DestApp = "nico_account_webpush"
)

type APIResponse struct {
	Meta struct {
		Status int `json:"status"`
	} `json:"meta"`
}

type Register struct {
	DestApp  DestApp  `json:"destApp"`
	Endpoint Endpoint `json:"endpoint"`
}

type Endpoint struct {
	Endpoint string `json:"endpoint"`
	Auth     string `json:"auth"`
	P256DH   string `json:"p256dh"`
}

// "data" property in WebPush Notification Message
type PushData struct {
	TTL               time.Duration `json:"ttl"` // e.g. 600
	CreatedAt         time.Time     `json:"created_at"`
	OnClick           string        `json:"on_click"`           // Program URL (e.g. "https://live.nicovideo.jp/watch/lv123456?from=webpush&_topic=live_user_program_onairs")
	TrackingParameter string        `json:"tracking_parameter"` // e.g. "live_onair-lv123456-webpush-nico_account_webpush"
}
