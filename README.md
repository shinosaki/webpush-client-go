# webpush-client-go

`webpush-client-go`は、Golangで実装されたWebPushを受信するためのクライアントおよびライブラリです。

## Features
- RFC8188メッセージの暗号化・復号
    - `aes128gcm`のみのサポート
- RFC8291メッセージの暗号化・復号
- AutoPush (Mozilla Push Service) のクライアント
- Application Serverごとのクライアント
    - NicoPush: https://www.nicovideo.jp

## Examples

[examples](./examples)を参照してください。

- [examples/ece](./examples/ece/main.go): 単純なRFC8291メッセージの暗号化・復号
- [examples/nicopush](./examples/nicopush/main.go): ニコニコのWebPush通知を受信します（AutoPush）

### NicoPush
`NICONICO_USER_SESSION_VALUE`に`nicovideo.jp`の`user_session`クッキーの値を指定してください。

```bash
echo '{"user_session":"NICONICO_USER_SESSION_VALUE"}' > config.json

go run ./examples/nicopush/main.go
```

## References
- RFCs
    - [RFC8188](https://tools.ietf.org/html/rfc8188): HTTP用のコンテンツ暗号化の仕様
        - [Content-Encoding: aes128gcm とは (RFC8188) - ASnoKaze blog](https://asnokaze.hatenablog.com/entry/20170202/1486046514): RFC8188の要旨を日本語で解説している
    - [RFC8291](https://tools.ietf.org/html/rfc8291): RFC8188を拡張した、プッシュ通知の暗号化の仕様
- Encrypt Content-Encoding
    - [web-push-libs/ecec](https://github.com/web-push-libs/ecec): RFC8188/RFC8291のC言語実装
    - [web-push-libs/encrypted-content-encoding](https://github.com/web-push-libs/encrypted-content-encoding): RFC8188/RFC8291のPython/Node.js実装（`http_ece`）
    - [web-push-libs/web-push-php](https://github.com/web-push-libs/web-push-php): ウェブプッシュサーバのPHP実装
        - [web-push-php/src/Encryption.php](https://github.com/web-push-libs/web-push-php/blob/7b6d1e9d202c31dd9d53929ae33be3f704df7034/src/Encryption.php): 暗号化ペイロード構築部分
- AutoPush
    - [Design - Mozilla Push Service Documentation](https://mozilla-push-service.readthedocs.io/en/latest/design/): Firefoxで使用されるプッシュサーバ（Mozilla Push Service）のドキュメント
    - [Architecture - Mozilla AutoPush Server](https://mozilla-services.github.io/autopush-rs/architecture.html): Mozilla Push ServiceのサーバであるAutoPushのドキュメント
    - [Architecture - autopush documentation](https://autopush.readthedocs.io/en/latest/architecture.html): 廃止されたAutoPushのPython実装のドキュメント
- WebPush
    - [Магия WebPush в Mozilla Firefox. Взгляд изнутри - Habr](https://habr.com/ru/articles/487494/): FirefoxのWebPush実装を解説している
    - [MANKAのBlog](https://blog.nest.moe)
        - [通过 Web Push 接收最新的推文](https://blog.nest.moe/posts/receive-latest-tweets-by-web-push): Twitterのプッシュ通知を例に、詳細を解説しているブログポスト
        - [解密来自 Web Push 的 AES-GCM 消息](https://blog.nest.moe/posts/decrypt-aesgcm-messages-from-web-push): 上記のポストの暗号化周りを詳細に解説している
    - [tomoyukilabs - Qiita](https://qiita.com/tomoyukilabs)
        - [Web Pushでブラウザにプッシュ通知を送ってみる](https://qiita.com/tomoyukilabs/items/217915676603fda73b0a)
        - [[改訂版] Web Pushでブラウザにプッシュ通知を送ってみる](https://qiita.com/tomoyukilabs/items/2ae4a0f708a1af75f13e)
    - [SherClockHolmes/webpush-go](https://github.com/SherClockHolmes/webpush-go): WebPush暗号化のGo実装
- NicoPush
    - [ニコ生のプッシュ通知の受信の手順 - nicoLiveCheckTool/push.md](https://github.com/guest-nico/nicoLiveCheckTool/blob/master/push.md): C#でニコニコのWebPush通知を受信する手順を解説している

## LICENSE
[MIT](./LICENSE)

## Author
[shinosaki](https://shinosaki.com)
