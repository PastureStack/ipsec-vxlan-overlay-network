package topology

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxInputBytes = 2 << 20

func Decode(r io.Reader) (Config, error) {
	limited := io.LimitReader(r, MaxInputBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Config{}, fmt.Errorf("read input: %w", err)
	}
	if len(data) > MaxInputBytes {
		return Config{}, fmt.Errorf("input exceeds %d bytes", MaxInputBytes)
	}
	if err := rejectDuplicateFields(data); err != nil {
		return Config{}, fmt.Errorf("decode input: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode input: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode input: multiple JSON documents are not allowed")
		}
		return Config{}, fmt.Errorf("decode input: %w", err)
	}
	return config, nil
}

func rejectDuplicateFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return scanJSONValue(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object field name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
