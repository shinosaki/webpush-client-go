package autopush

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/shinosaki/webpush-client-go/rfc8291"
	"github.com/shinosaki/webpush-client-go/webpush"
	"github.com/shinosaki/websocket-client-go/websocket"
)

const MOZILLA_PUSH_SERVICE = "wss://push.services.mozilla.com"

type AutoPushClient struct {
	*websocket.WebSocketClient
	ece              *rfc8291.RFC8291
	helloChan        chan HelloResponse
	notificationChan chan Notification
	registerChan     chan RegisterResponse
	unregisterChan   chan UnregisterResponse
}

func request[T any](c *AutoPushClient, ch chan T, timeout time.Duration, timeoutErr string, payload any) (res T, err error) {
	if err := c.SendJSON(payload); err != nil {
		log.Println("websocket request failed", err)
	}

	select {
	case res := <-ch:
		return res, err
	case <-time.After(timeout * time.Second):
		return res, errors.New(timeoutErr)
	}
}

func unmarshaler[T any](payload json.RawMessage, label MessageType) (data *T) {
	// log.Println("autopush: before unmarshal payload", payload)
	if err := json.Unmarshal(payload, &data); err != nil {
		log.Printf("AutoPush: failed to unmarshal %s payload: %v", label, err)
	}
	return data
}

func (c *AutoPushClient) Hello(uaid string, channelIDs []string) (HelloResponse, error) {
	return request(c, c.helloChan, 5, "hello timeout", HelloRequest{
		Type:       HELLO,
		UAID:       uaid,
		ChannelIDs: channelIDs,
		UseWebPush: true,
	})
}

func (c *AutoPushClient) Register(channelID string, vapidKey string) (RegisterResponse, error) {
	return request(c, c.registerChan, 5, "register timeout", RegisterRequest{
		Type:      REGISTER,
		ChannelID: channelID,
		Key:       vapidKey,
	})
}

func (c *AutoPushClient) Unregister(channelID string) (UnregisterResponse, error) {
	return request(c, c.unregisterChan, 5, "unregister timeout", UnregisterRequest{
		Type:      UNREGISTER,
		ChannelID: channelID,
	})
}

func (c *AutoPushClient) Decrypt(
	curve ecdh.Curve,
	authSecret []byte,
	useragentPrivateKey *ecdh.PrivateKey,
	notification Notification,
) (*webpush.WebPushPayload, error) {
	data, err := base64.RawURLEncoding.DecodeString(notification.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %v", err)
	}

	payload, err := rfc8291.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("rfc8291 decode error: %v", err)
	}

	appserverPublicKey, err := curve.NewPublicKey(payload.KeyId)
	if err != nil {
		return nil, fmt.Errorf("ecdh public key load error: %v", err)
	}

	plaintext, err := c.ece.Decrypt(
		payload.CipherText,
		payload.Salt,
		authSecret,
		useragentPrivateKey,
		appserverPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("rfc8291 decrypt error: %v", err)
	}

	var result webpush.WebPushPayload
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %v", err)
	}
	return &result, nil
}

func NewAutoPushClient() (ap *AutoPushClient, ch chan Notification) {
	ap = &AutoPushClient{
		ece:              rfc8291.NewRFC8291(sha256.New),
		helloChan:        make(chan HelloResponse),
		notificationChan: make(chan Notification),
		registerChan:     make(chan RegisterResponse),
		unregisterChan:   make(chan UnregisterResponse),
		WebSocketClient: websocket.NewWebSocketClient(
			nil,
			func(ws *websocket.WebSocketClient, isReconnecting bool) {
				if !isReconnecting {
					close(ap.helloChan)
					close(ap.notificationChan)
					close(ap.registerChan)
					close(ap.unregisterChan)
				}
			},
			func(ws *websocket.WebSocketClient, payload []byte) {
				// log.Println("AutoPush Received Message:", string(payload))
				var message Message
				if err := json.Unmarshal(payload, &message); err != nil {
					log.Println("AutoPush: failed to unmarshal payload", err)
					return
				}

				switch message.Type {
				case PING:
					ws.SendJSON("{}")

				case HELLO:
					if data := unmarshaler[HelloResponse](payload, HELLO); data != nil {
						ap.helloChan <- *data
					}

				case REGISTER:
					if data := unmarshaler[RegisterResponse](payload, REGISTER); data != nil {
						ap.registerChan <- *data
					}

				case UNREGISTER:
					if data := unmarshaler[UnregisterResponse](payload, UNREGISTER); data != nil {
						ap.unregisterChan <- *data
					}

				case NOTIFICATION:
					if data := unmarshaler[Notification](payload, NOTIFICATION); data != nil {
						ws.SendJSON(Ack{
							Type: ACK,
							Updates: []AckUpdate{
								{
									ChannelID: data.ChannelID,
									Version:   data.Version,
								},
							},
						})
						ap.notificationChan <- *data
					}

				default:
					log.Println("AutoPush: unknown data type", message.Type)
				}
			},
		),
	}

	return ap, ap.notificationChan
}
