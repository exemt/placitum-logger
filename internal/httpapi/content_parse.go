package httpapi

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"
)

func parseHeadersFragment(data []byte) (pairs []pair, continuation string) {
	if rows := parseHeaders(data); rows != nil {
		return rows, ""
	}

	return scanHeaders(data)
}

func parseArgsFragment(raw string, offset int64) (pairs []pair, continuation string) {
	if raw == "" {
		return nil, ""
	}

	if offset > 0 && raw[0] != '&' {
		head, rest, found := strings.Cut(raw, "&")
		if found && rest != "" {
			return parseArgs(rest), unescape(head)
		}

		return nil, unescape(head)
	}

	return parseArgs(raw), ""
}

func utf8Window(data []byte) (string, int, bool) {
	if bytes.IndexByte(data, 0) >= 0 {
		return "", 0, false
	}

	if utf8.Valid(data) {
		return string(data), len(data), true
	}

	end := len(data)
	for end > 0 && data[end-1]&0xC0 == 0x80 {
		end--
	}
	if end > 0 && data[end-1]&0x80 != 0 {
		end--
	}
	if end == 0 || !utf8.Valid(data[:end]) {
		return "", 0, false
	}

	return string(data[:end]), end, true
}

func scanHeaders(data []byte) (pairs []pair, continuation string) {
	i := skipSpace(data, 0)
	if i >= len(data) {
		return nil, ""
	}

	switch data[i] {
	case '[':
		j := skipSpace(data, i+1)
		if j < len(data) && data[j] == '[' {
			i = j
		}

	case ',':
		i = skipSpace(data, i+1)

	default:
		return nil, unescapeJSONFragment(string(data[i:]))
	}

	for i < len(data) {
		i = skipSpace(data, i)
		if i >= len(data) {
			break
		}

		switch data[i] {
		case ']':
			return pairs, continuation

		case ',':
			i++
			continue

		case '[':
			item, next, complete, ok := readPair(data, i)
			if !ok {
				return pairs, unescapeJSONFragment(string(data[i:]))
			}

			pairs = append(pairs, item)
			i = next
			if !complete {
				return pairs, continuation
			}

		default:
			return pairs, unescapeJSONFragment(string(data[i:]))
		}
	}

	return pairs, continuation
}

func readPair(data []byte, i int) (p pair, next int, complete, ok bool) {
	i = skipSpace(data, i)
	if i >= len(data) || data[i] != '[' {
		return pair{}, i, false, false
	}

	i++
	name, i, nameDone, nameOK := readJSONString(data, i)
	if !nameOK {
		return pair{}, i, false, false
	}

	p.Name = name
	ok = true
	if !nameDone {
		return p, len(data), false, true
	}

	i = skipSpace(data, i)
	if i < len(data) && data[i] == ',' {
		i++
	}

	value, i, valueDone, valueOK := readJSONString(data, i)
	if !valueOK {
		return p, len(data), false, true
	}

	p.Value = value
	if !valueDone {
		return p, len(data), false, true
	}

	i = skipSpace(data, i)
	if i < len(data) && data[i] == ']' {
		i++
	}

	return p, i, true, true
}

func readJSONString(data []byte, i int) (s string, next int, complete, ok bool) {
	i = skipSpace(data, i)
	if i >= len(data) {
		return "", i, false, false
	}
	if data[i] != '"' {
		return "", i, false, false
	}

	i++
	var b strings.Builder

	for i < len(data) {
		c := data[i]
		if c == '"' {
			return b.String(), i + 1, true, true
		}

		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}

		if i+1 >= len(data) {
			return b.String(), len(data), false, true
		}

		i++
		switch data[i] {
		case '"', '\\', '/':
			b.WriteByte(data[i])
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			if i+4 >= len(data) {
				return b.String(), len(data), false, true
			}

			r, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 32)
			if err != nil {
				b.WriteByte('u')
			} else {
				b.WriteRune(rune(r))
				i += 4
			}
		default:
			b.WriteByte(data[i])
		}

		i++
	}

	return b.String(), len(data), false, true
}

func unescapeJSONFragment(s string) string {
	got, _, _, ok := readJSONString([]byte(`"`+s), 0)
	if !ok {
		return s
	}

	return got
}

func skipSpace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}

	return i
}
