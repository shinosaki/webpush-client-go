package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"github.com/shinosaki/webpush-client-go/rfc8291"
	"github.com/shinosaki/webpush-client-go/sites/nicopush"
)

type Config struct {
	UserSession string
	AuthSecret  []byte
	PrivateKey  *ecdh.PrivateKey
	UAID        string
	ChannelIDs  []string
}

type SerializedConfig struct {
	UserSession string   `json:"user_session"`
	AuthSecret  string   `json:"auth_secret"`
	PrivateKey  string   `json:"private_key"`
	UAID        string   `json:"uaid"`
	ChannelIDs  []string `json:"channel_ids"`
}

func ConfigLoad(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	serialized := &SerializedConfig{}

	if err := json.NewDecoder(file).Decode(&serialized); err != nil {
		log.Println("failed to load config:", err)
	}

	var (
		authSecret []byte
		privateKey *ecdh.PrivateKey
	)

	authSecret, _, privateKey = rfc8291.NewSecrets(ecdh.P256())

	if serialized.AuthSecret != "" {
		authSecret, _ = base64.RawURLEncoding.DecodeString(serialized.AuthSecret)
	}

	if serialized.PrivateKey != "" {
		b, _ := base64.RawURLEncoding.DecodeString(serialized.PrivateKey)
		privateKey, _ = ecdh.P256().NewPrivateKey(b)
	}

	config.UserSession = serialized.UserSession
	config.AuthSecret = authSecret
	config.PrivateKey = privateKey
	config.UAID = serialized.UAID
	config.ChannelIDs = serialized.ChannelIDs

	return config, nil
}

func ConfigSave(path string, config *Config) error {
	serialized := &SerializedConfig{
		UserSession: config.UserSession,
		UAID:        config.UAID,
		ChannelIDs:  config.ChannelIDs,
		AuthSecret:  base64.RawURLEncoding.EncodeToString(config.AuthSecret),
		PrivateKey:  base64.RawURLEncoding.EncodeToString(config.PrivateKey.Bytes()),
	}

	data, err := json.MarshalIndent(serialized, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func main() {
	configPath := "config.json"

	config, err := ConfigLoad(configPath)
	if err != nil {
		panic(err)
	}

	if config.UserSession == "" {
		panic("user session is require")
	}

	httpClient, err := nicopush.NewLoginSession(config.UserSession)
	if err != nil {
		panic(err)
	}

	nicoPushClient, notificationChan, err := nicopush.NewNicoPushClient(
		config.UAID,
		config.ChannelIDs,
		config.AuthSecret,
		config.PrivateKey,
		httpClient,
	)
	if err != nil {
		panic(err)
	}

	config.UAID, err = nicoPushClient.Handshake()
	if err != nil {
		panic(err)
	}
	log.Println("UAID:", config.UAID)
	ConfigSave(configPath, config)

	if len(config.ChannelIDs) == 0 {
		channelID, err := nicoPushClient.Register()
		if err != nil {
			panic(err)
		}
		log.Println("ChannelID:", channelID)

		config.ChannelIDs = append(config.ChannelIDs, channelID)
		ConfigSave(configPath, config)
	}

	for data := range notificationChan {
		payload, err := nicoPushClient.Decrypt(data)
		if err != nil {
			log.Println("webpush error:", err)
			continue
		}

		log.Println("Title:", payload.Title)
		log.Println("Body: ", payload.Body)
		log.Println("Icon: ", payload.Icon)

		var pushData nicopush.PushData
		if err := json.Unmarshal(payload.Data, &pushData); err != nil {
			log.Println("push data parse error:", err)
			continue
		}
		log.Println("URL:       ", pushData.OnClick)
		log.Println("CreatedAt: ", pushData.CreatedAt)
	}
}
