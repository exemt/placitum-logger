/*
 * Архив: GetObject и подпись SigV4, больше ничего.
 *
 * Зеркало клиента архивации у агента (nginx/agent/internal/retain/s3.go) — там
 * кладут, здесь берут. Своя подпись вместо SDK по той же причине: из него нужна
 * одна функция на пять HMAC, а приходит с ним разрешение регионов, цепочки
 * реквизитов и полсотни транзитивных модулей.
 *
 * Path-style адресация (/bucket/key) — единственная, работающая и с MinIO, и с
 * Ceph RGW, и с AWS без DNS-обвязки.
 */

package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	s3Algorithm = "AWS4-HMAC-SHA256"
	s3Service   = "s3"
	s3Time      = "20060102T150405Z"
	s3Date      = "20060102"

	// Хеш пустого тела: у GET его нет, но подписать содержимое всё равно надо.
	s3EmptyBody = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type s3Client struct {
	endpoint string
	region   string
	access   string
	secret   string
	http     *http.Client
}

/*
 * get забирает окно объекта: offset байт от начала, не больше limit. Карточка
 * догружает следующее окно по scroll, и без Range каждый раз читала бы объект
 * с нуля. «Есть ещё» берём из Content-Range либо из лишнего байта на чтении:
 * Range сам по себе не отличает «объект ровно такой» от «объект больше».
 */
func (c *s3Client) get(ctx context.Context, bucket, key string, offset, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		return nil, false, fmt.Errorf("store: limit must be positive")
	}
	if offset < 0 {
		offset = 0
	}

	url := c.endpoint + "/" + bucket + "/" + uriEncode(key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	now := time.Now().UTC()
	end := offset + limit - 1

	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))
	req.Header.Set("X-Amz-Content-Sha256", s3EmptyBody)
	req.Header.Set("X-Amz-Date", now.Format(s3Time))

	c.sign(req, s3EmptyBody, now)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, false, ErrGone
	}

	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		_, _ = io.Copy(io.Discard, resp.Body)
		return []byte{}, false, nil
	}

	if resp.StatusCode/100 != 2 {
		// Тело ошибки S3 — XML с кодом и сообщением; разбирать его незачем, а
		// показать в журнале стоит: без него «403» не отличить от «нет бакета».
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

		return nil, false, fmt.Errorf("store: s3 %s: %s", resp.Status,
			strings.TrimSpace(string(detail)))
	}

	if resp.StatusCode == http.StatusOK {
		return readFullWindow(resp.Body, offset, limit)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, false, err
	}

	clipped := int64(len(data)) > limit
	if clipped {
		data = data[:limit]
	}

	if more, ok := rangeHasMore(resp.Header.Get("Content-Range"), offset+int64(len(data))); ok {
		clipped = more
	}

	return data, clipped, nil
}

// readFullWindow — хранилище проигнорировало Range и отдало объект целиком.
// Режем окно сами и не читаем дальше offset+limit+1: иначе мегабайтное тело
// снова оказалось бы в карточке целиком.
func readFullWindow(body io.Reader, offset, limit int64) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(body, offset+limit+1))
	if err != nil {
		return nil, false, err
	}

	if offset >= int64(len(buf)) {
		return []byte{}, false, nil
	}

	end := offset + limit
	clipped := int64(len(buf)) > end
	if end > int64(len(buf)) {
		end = int64(len(buf))
	}

	return buf[offset:end], clipped, nil
}

// rangeHasMore разбирает Content-Range: bytes start-end/total. total < 0
// (звёздочка) — длины нет, и по заголовку уже не сказать.
func rangeHasMore(hdr string, next int64) (more bool, ok bool) {
	const prefix = "bytes "

	s := strings.TrimSpace(hdr)
	if !strings.HasPrefix(strings.ToLower(s), prefix) {
		return false, false
	}

	s = strings.TrimSpace(s[len(prefix):])
	_, total, found := strings.Cut(s, "/")
	if !found || total == "" || total == "*" {
		return false, false
	}

	n, err := strconv.ParseInt(total, 10, 64)
	if err != nil || n < 0 {
		return false, false
	}

	return next < n, true
}

// sign — SigV4 над уже собранным запросом. Подписываются только те заголовки,
// которые мы сами и поставили: чем короче список подписанных, тем меньше
// поводов у прокси между нами и хранилищем сломать подпись. Range входит в
// подпись, иначе хранилище отвергнет окно как чужой заголовок.
func (c *s3Client) sign(req *http.Request, hash string, now time.Time) {
	date := now.Format(s3Date)
	stamp := now.Format(s3Time)

	headers := [][2]string{
		{"host", req.URL.Host},
		{"x-amz-content-sha256", hash},
		{"x-amz-date", stamp},
	}
	if rng := req.Header.Get("Range"); rng != "" {
		headers = append(headers, [2]string{"range", rng})
	}

	sort.Slice(headers, func(i, j int) bool { return headers[i][0] < headers[j][0] })

	names := make([]string, len(headers))
	var canonical strings.Builder

	canonical.WriteString(req.Method)
	canonical.WriteString("\n")
	canonical.WriteString(req.URL.EscapedPath())
	canonical.WriteString("\n\n")

	for i, h := range headers {
		names[i] = h[0]
		canonical.WriteString(h[0])
		canonical.WriteString(":")
		canonical.WriteString(h[1])
		canonical.WriteString("\n")
	}

	signed := strings.Join(names, ";")

	canonical.WriteString("\n")
	canonical.WriteString(signed)
	canonical.WriteString("\n")
	canonical.WriteString(hash)

	sum := sha256.Sum256([]byte(canonical.String()))
	scope := date + "/" + c.region + "/" + s3Service + "/aws4_request"

	toSign := s3Algorithm + "\n" + stamp + "\n" + scope + "\n" +
		hex.EncodeToString(sum[:])

	key := hmacSHA256([]byte("AWS4"+c.secret), date)
	key = hmacSHA256(key, c.region)
	key = hmacSHA256(key, s3Service)
	key = hmacSHA256(key, "aws4_request")

	signature := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", s3Algorithm+
		" Credential="+c.access+"/"+scope+
		", SignedHeaders="+signed+
		", Signature="+signature)
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))

	return mac.Sum(nil)
}

// uriEncode — кодирование по правилам SigV4. S3 — единственный сервис, где путь
// в каноническом запросе не кодируется повторно, поэтому кодировать его надо
// ровно один раз и ровно так же, как он уедет в строке запроса.
func uriEncode(s string) string {
	var out strings.Builder

	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == '/':
			out.WriteByte(c)

		default:
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}

	return out.String()
}
