// Package certgen 对应原脚本这几行：
//
//	openssl req -x509 -newkey rsa:2048 -nodes \
//	  -keyout "${WORKDIR}/key.tmp" -out "${WORKDIR}/cert.tmp" \
//	  -days 3650 -subj "/CN=${BEST_DOMAIN}" \
//	  -addext "subjectAltName=DNS:${BEST_DOMAIN}"
//
// 用标准库 crypto/x509 原生生成，不再依赖系统里的 openssl 二进制。
package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// SelfSigned 生成一份自签名证书，返回值是按行拆开的 PEM 文本（含
// "-----BEGIN/END-----" 这两行），跟 sing-box 配置里 tls.certificate /
// tls.key 字段接受的"逐行数组"格式一致——这是原脚本用 awk 把 PEM 文件拆行
// 拼进 JSON 数组的写法，这里直接原生生成同样的结构，不需要中间文件。
func SelfSigned(commonName string) (certLines, keyLines []string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 RSA 密钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书序列号失败: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-5 * time.Minute), // 留一点时钟误差余量
		NotAfter:              time.Now().AddDate(0, 0, 3650),   // 对应 -days 3650
		DNSNames:              []string{commonName},             // 对应 subjectAltName=DNS:...
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书失败: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("编码私钥失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return splitLines(certPEM), splitLines(keyPEM), nil
}

func splitLines(pemBytes []byte) []string {
	return strings.Split(strings.TrimRight(string(pemBytes), "\n"), "\n")
}
