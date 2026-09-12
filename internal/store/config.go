/*
 * Настройка чтения архива: окружение, как и всё остальное у поиска.
 *
 * Реквизиты и бакеты живут здесь, а не на проводе, — ровно по той же причине,
 * по которой их держит у себя агент (nginx/agent/internal/retain/config.go):
 * локатор называет ключ и драйвер, а куда именно ходить за этим ключом, решает
 * тот, кто ходит. Поэтому смена бакета не трогает ни одну запись аудита.
 *
 * Горячего обменника здесь нет: до записи аудита он не доживает, и адреса Redis
 * поиску знать незачем. См. store.go.
 *
 * Ничего не задано — чтение архива выключено, и это не ошибка: поиск по
 * позвоночнику работает и без него, а карточка честно скажет, что содержимое
 * недоступно.
 */

package store

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRegion    = "us-east-1"
	defaultOpTimeout = 5 * time.Second

	/*
	 * Потолок одного окна. Карточку читают глазами в браузере, а тела в
	 * архиве бывают мегабайтные: отдать их целиком в JSON значит подвесить
	 * вкладку, а не показать инцидент. Дальше карточка просит следующее окно.
	 */
	defaultMaxBytes = 256 << 10
)

type Config struct {
	S3 S3Config

	// Bucket — назначение по виду объекта. Разведены по бакетам не из
	// аккуратности: у тела, заголовков и строки запроса разная
	// чувствительность, а значит разные политики доступа. Пусто для вида —
	// архив этого вида поиску не открыт.
	Bucket map[string]string

	MaxBytes  int64
	OpTimeout time.Duration
}

type S3Config struct {
	Endpoint string
	Region   string
	Access   string
	Secret   string
}

func FromEnv() (Config, error) {
	cfg := Config{
		Bucket: map[string]string{
			"headers": os.Getenv("WAF_STORE_BUCKET_HEADERS"),
			"args":    os.Getenv("WAF_STORE_BUCKET_ARGS"),
			"body":    os.Getenv("WAF_STORE_BUCKET_BODY"),
		},
		S3: S3Config{
			Endpoint: strings.TrimRight(os.Getenv("WAF_STORE_S3_ENDPOINT"), "/"),
			Region:   os.Getenv("WAF_STORE_S3_REGION"),
		},
	}

	if err := cfg.readCredentials(
		os.Getenv("WAF_STORE_S3_CREDENTIALS_FILE")); err != nil {
		return Config{}, err
	}

	if cfg.S3.Access == "" {
		cfg.S3.Access = os.Getenv("WAF_STORE_S3_ACCESS_KEY")
	}

	if cfg.S3.Secret == "" {
		cfg.S3.Secret = os.Getenv("WAF_STORE_S3_SECRET_KEY")
	}

	var err error

	if cfg.MaxBytes, err = size("WAF_STORE_MAX_BYTES", defaultMaxBytes); err != nil {
		return Config{}, err
	}

	if cfg.OpTimeout, err = span("WAF_STORE_OP_TIMEOUT", defaultOpTimeout); err != nil {
		return Config{}, err
	}

	cfg.normalize()

	// Задано криво — ошибка на старте. Тихо деградировать в «архива нет»
	// значит однажды не показать доказательную базу и не понять почему.
	if cfg.S3.Endpoint != "" && (cfg.S3.Access == "" || cfg.S3.Secret == "") {
		return Config{}, fmt.Errorf(
			"WAF_STORE_S3_ENDPOINT is set but credentials are empty")
	}

	return cfg, nil
}

// ArchiveEnabled — открыт ли поиску архив хотя бы одного вида.
func (c Config) ArchiveEnabled() bool {
	if c.S3.Endpoint == "" || c.S3.Access == "" || c.S3.Secret == "" {
		return false
	}

	for _, kind := range Kinds {
		if c.Bucket[kind] != "" {
			return true
		}
	}

	return false
}

func (c *Config) normalize() {
	if c.Bucket == nil {
		c.Bucket = map[string]string{}
	}

	if c.S3.Region == "" {
		c.S3.Region = defaultRegion
	}

	if c.MaxBytes <= 0 {
		c.MaxBytes = defaultMaxBytes
	}

	if c.OpTimeout <= 0 {
		c.OpTimeout = defaultOpTimeout
	}
}

// readCredentials читает реквизиты из файла, а не из окружения: окружение
// процесса видно соседям по машине и уезжает в дампы, а у файла есть режим и
// владелец. Формат — те же ключи, что у ~/.aws/credentials, без секций.
func (c *Config) readCredentials(path string) error {
	if path == "" {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("WAF_STORE_S3_CREDENTIALS_FILE: %w", err)
	}

	defer f.Close()

	scan := bufio.NewScanner(f)

	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())

		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "[") {
			continue
		}

		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch strings.TrimSpace(name) {
		case "aws_access_key_id", "access_key":
			c.S3.Access = strings.TrimSpace(value)
		case "aws_secret_access_key", "secret_key":
			c.S3.Secret = strings.TrimSpace(value)
		}
	}

	if err := scan.Err(); err != nil {
		return fmt.Errorf("WAF_STORE_S3_CREDENTIALS_FILE: %w", err)
	}

	return nil
}

func size(key string, fallback int64) (int64, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: expected a positive number, got %q", key, value)
	}

	return n, nil
}

func span(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: expected a duration, got %q", key, value)
	}

	return d, nil
}
