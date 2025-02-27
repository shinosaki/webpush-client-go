package nicopush

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/shinosaki/webpush-client-go/autopush"
	"github.com/shinosaki/webpush-client-go/rfc8291"
	"github.com/shinosaki/webpush-client-go/webpush"
)

type NicoPushClient struct {
	autoPushClient *autopush.AutoPushClient
	httpClient     *http.Client
	ece            *rfc8291.RFC8291

	vapidKey         []byte
	nicoPushEndpoint string

	uaid       string
	channelIDs []string
	authSecret []byte
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

func NewNicoPushClient(
	uaid string,
	channelIDs []string,
	authSecret []byte,
	privateKey *ecdh.PrivateKey,
	httpClient *http.Client,
) (*NicoPushClient, chan autopush.Notification, error) {
	vapidKey, nicoPushEndpoint, err := getEndpointAndVapidKey()
	if err != nil {
		return nil, nil, err
	}

	ap, ch := autopush.NewAutoPushClient()

	client := &NicoPushClient{
		autoPushClient: ap,
		httpClient:     httpClient,
		ece:            rfc8291.NewRFC8291(sha256.New),

		vapidKey:         vapidKey,
		nicoPushEndpoint: nicoPushEndpoint,

		uaid:       uaid,
		channelIDs: channelIDs,
		authSecret: authSecret,
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
	}

	return client, ch, nil
}

// Handshake performs a handshake with the AutoPush server and retrieves a UAID.
// The obtained UAID is used for client identification and should be saved.
func (c *NicoPushClient) Handshake() (uaid string, err error) {
	if err := c.autoPushClient.Connect(autopush.MOZILLA_PUSH_SERVICE, 3, 2); err != nil {
		return "", fmt.Errorf("failed to connect autopush server: %v", err)
	}

	data, err := c.autoPushClient.Hello(c.uaid, c.channelIDs)
	if err != nil {
		return "", fmt.Errorf("failed to handshake autopush server: %v", err)
	}

	c.uaid = data.UAID
	return c.uaid, nil
}

func (c *NicoPushClient) Register() (channelID string, err error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUIDv4: %v", err)
	}

	data, err := c.autoPushClient.Register(uuid.String(), base64.StdEncoding.EncodeToString(c.vapidKey))
	if err != nil {
		return "", fmt.Errorf("failed to register autopush: %v", err)
	}

	if err := c.registerToAppServer(data.PushEndpoint); err != nil {
		return "", fmt.Errorf("failed to register nicopush: %v", err)
	}

	return uuid.String(), nil
}

func (c *NicoPushClient) Decrypt(data autopush.Notification) (*webpush.WebPushPayload, error) {
	return c.autoPushClient.Decrypt(
		ecdh.P256(),
		c.authSecret,
		c.privateKey,
		data,
	)
}

// Registration AutoPush's push-endpoint to NicoPush (Application Server)
func (c *NicoPushClient) registerToAppServer(pushEndpoint string) error {
	payload, err := json.Marshal(Register{
		DestApp: NICO_ACCOUNT_WEBPUSH,
		Endpoint: Endpoint{
			Endpoint: pushEndpoint,
			Auth:     base64.StdEncoding.EncodeToString(c.authSecret),
			P256DH:   base64.StdEncoding.EncodeToString(c.publicKey.Bytes()),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal register payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.nicoPushEndpoint, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to bulid register request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-With", "https://account.nicovideo.jp/my/account")
	req.Header.Set("X-Frontend-Id", "8")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("nicopush register request failed: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid http status: %d %s", res.StatusCode, res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read error: %v", err)
	}

	var data APIResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("failed to unmarshal api response: %v", err)
	}

	if data.Meta.Status != http.StatusOK {
		return fmt.Errorf("invalid response status: %d", data.Meta.Status)
	}

	return nil
}
