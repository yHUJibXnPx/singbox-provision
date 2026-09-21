package randgen

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// RealityKeyPair 生成一对 X25519 密钥，编码格式（32 字节原始密钥、
// base64 URL-safe、无 padding）跟 `sing-box generate reality-keypair` 的输出
// 完全一致——这一点是拿真实 sing-box 二进制核对过的，不是猜的：
//
//	$ sing-box generate reality-keypair
//	PrivateKey: kJKYCN2xk3QkhWa_w79jei6_yj5b42c9FOoqxwuH01w   (43 字符)
//	PublicKey:  qIZb8h9A_0QnEw-RmJPu1psTLUfh_ktu9mw3uCekmQo   (43 字符)
//
// 43 字符、包含 '-'/'_'、无 '='，正是 32 字节做 base64.RawURLEncoding 的长度，
// 用 python 解码验证过确实是 32 字节。所以这里可以完全脱离 sing-box 二进制，
// 用标准库 crypto/ecdh 自己生成，部署机器上只需要 sing-box 本体去"跑"这个
// 配置，不需要再靠它来"生成"密钥。
func RealityKeyPair() (privateKey, publicKey string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("生成 X25519 密钥对失败: %w", err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privB64, pubB64, nil
}
