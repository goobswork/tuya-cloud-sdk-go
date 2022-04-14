package common

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/tuya/tuya-cloud-sdk-go/config"
)

func GetBizSign(token, timestamp string) string {
	sign := strings.ToUpper(HmacSha256(config.AccessID+token+timestamp, config.AccessKey))
	return sign
}

func GetEasySign(timestamp string) string {
	sign := strings.ToUpper(HmacSha256(config.AccessID+timestamp, config.AccessKey))
	return sign
}

func GetBizSignV2(req *http.Request, token string) string {
	contentSha256 := ""
	if req.Body != nil {
		buf, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
		contentSha256 = GetSha256(buf)
	} else {
		contentSha256 = GetSha256([]byte(""))
	}

	headers := getHeaderStr(req)
	urlStr := getUrlStr(req)

	stringToSign := req.Method + "\n" + contentSha256 + "\n" + headers + "\n" + urlStr
	// nonce := req.Header.Get("nonce")
	t := req.Header.Get("t")
	str := config.AccessID + token + t + stringToSign
	sign := strings.ToUpper(HmacSha256(str, config.AccessKey))
	return sign
}

func GetEasySignV2(req *http.Request) string {
	sign := GetBizSignV2(req, "")
	return sign
}

func GetSha256(data []byte) string {
	sha256Contain := sha256.New()
	sha256Contain.Write(data)
	return hex.EncodeToString(sha256Contain.Sum(nil))
}

func HmacSha256(data, key string) string {

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(key))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

func getHeaderStr(req *http.Request) string {
	signHeaderKeys := req.Header.Get("Signature-Headers")
	if signHeaderKeys == "" {
		return ""
	}
	keys := strings.Split(signHeaderKeys, ":")
	headers := ""
	for _, key := range keys {
		headers += key + ":" + req.Header.Get(key) + "\n"
	}
	return headers
}

func getUrlStr(req *http.Request) string {
	uri := req.URL.Path
	keys := make([]string, 0, 10)

	query := req.URL.Query()
	for key, _ := range query {
		keys = append(keys, key)
	}
	if len(keys) > 0 {
		uri += "?"
		sort.Strings(keys)
		for _, keyName := range keys {
			value := query.Get(keyName)
			uri += keyName + "=" + value + "&"
		}
	}

	if uri[len(uri)-1] == '&' {
		uri = uri[:len(uri)-1]
	}
	return uri
}
