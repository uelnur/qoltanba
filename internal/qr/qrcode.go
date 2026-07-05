package qr

import (
	"encoding/base64"

	qrcode "github.com/skip2/go-qrcode"
)

// qrPNGSize is the rendered QR edge in pixels. Medium recovery tolerates a bit of
// occlusion (e.g. a centered logo the consumer may overlay).
const qrPNGSize = 512

// encodeQRBase64 renders payload as a PNG QR code and returns it base64-encoded,
// ready for the consumer to drop into an <img src="data:image/png;base64,…">.
func encodeQRBase64(payload string) (string, error) {
	png, err := qrcode.Encode(payload, qrcode.Medium, qrPNGSize)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(png), nil
}
