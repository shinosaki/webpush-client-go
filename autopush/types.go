package autopush

type Status int

const (
	OK           Status = 200
	CONFLICT     Status = 409
	SERVER_ERROR Status = 500
)

type MessageType string

const (
	PING         MessageType = "ping"
	ACK          MessageType = "ack"
	HELLO        MessageType = "hello"
	REGISTER     MessageType = "register"
	UNREGISTER   MessageType = "unregister"
	NOTIFICATION MessageType = "notification"
)

type Message struct {
	Type MessageType `json:"messageType"`
	// Data json.RawMessage `json:"-"`
}

type HelloRequest struct {
	Type       MessageType `json:"messageType"`
	UAID       string      `json:"uaid"`
	ChannelIDs []string    `json:"channelIDs"`
	UseWebPush bool        `json:"use_webpush,omitempty"`
}

type HelloResponse struct {
	Type       MessageType `json:"messageType"`
	UAID       string      `json:"uaid"`
	Status     Status      `json:"status"`
	UseWebPush bool        `json:"use_webpush,omitempty"`
	// Broadcasts map[string]any `json:"broadcasts"`
}

type RegisterRequest struct {
	Type      MessageType `json:"messageType"`
	ChannelID string      `json:"channelID"`
	Key       string      `json:"key"`
}

type RegisterResponse struct {
	Type         MessageType `json:"messageType"`
	ChannelID    string      `json:"channelID"`
	Status       Status      `json:"status"`
	PushEndpoint string      `json:"pushEndpoint"`
}

type UnregisterRequest struct {
	Type      MessageType `json:"messageType"`
	ChannelID string      `json:"channelID"`
}

type UnregisterResponse struct {
	Type      MessageType `json:"messageType"`
	ChannelID string      `json:"channelID"`
	Status    Status      `json:"status"`
}

type Notification struct {
	Type      MessageType         `json:"messageType"`
	ChannelID string              `json:"channelID"`
	Version   string              `json:"version"`
	Data      string              `json:"data"`
	Headers   NotificationHeaders `json:"headers"`
}

type NotificationHeaders struct {
	Encryption string `json:"encryption"`
	CryptoKey  string `json:"crypto_key"`
	Encoding   string `json:"encoding"`
}

type Ack struct {
	Type    MessageType `json:"messageType"`
	Updates []AckUpdate `json:"updates"`
}

type AckUpdate struct {
	ChannelID string `json:"channelID"`
	Version   string `json:"version"`
}
