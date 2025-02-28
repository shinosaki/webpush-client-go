package nicopush

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
)

func NewLoginSession(userSession string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	origin, _ := url.Parse("https://nicovideo.jp/")
	jar.SetCookies(origin, []*http.Cookie{
		{
			Name:   "user_session",
			Value:  userSession,
			Path:   "/",
			Domain: ".nicovideo.jp",
		},
	})

	client := &http.Client{
		Transport: &http2.Transport{},
		Jar:       jar,
	}

	return client, nil
}

func getEndpointAndVapidKey() (vapidKey []byte, nicoPushUrl string, err error) {
	fetchString := func(url string) (string, error) {
		res, err := http.Get(url)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			return "", fmt.Errorf("invalid http status %d %s", res.StatusCode, res.Status)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return "", err
		}

		return string(body), nil
	}

	getServiceWorkerUrl := func() (string, error) {
		body, err := fetchString("https://account.nicovideo.jp/sw.js")
		if err != nil {
			return "", err
		}

		re := regexp.MustCompile(`importScripts\(['"](.*?)['"]\)`)
		match := re.FindStringSubmatch(string(body))
		if len(match) != 2 {
			return "", errors.New("importScript is not contain")
		}

		return match[1], nil
	}

	swUrl, err := getServiceWorkerUrl()
	if err != nil {
		return vapidKey, nicoPushUrl, err
	}
	log.Println("swURL:", swUrl)

	swFile, err := fetchString(swUrl)
	if err != nil {
		return vapidKey, nicoPushUrl, err
	}

	re := regexp.MustCompile(`Uint8Array\(\[([\d,]+)\]\);[\w.]+={URL:"(https:\/\/api\.push\.nicovideo\.jp.*?)"`)
	match := re.FindStringSubmatch(swFile)
	if len(match) != 3 {
		return vapidKey, nicoPushUrl, errors.New("VAPID key and NicoPush url is not contain")
	}

	byteStrings := match[1]
	nicoPushUrl = match[2]

	nums := strings.Split(byteStrings, ",")
	vapidKey = make([]byte, len(nums))
	for i, s := range nums {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return vapidKey, nicoPushUrl, fmt.Errorf("failed to convert byte arrays of Uint8Array strings: %v", err)
		}
		vapidKey[i] = byte(n)
	}

	return vapidKey, nicoPushUrl, nil
}
