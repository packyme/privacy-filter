package env

import "os"

func String(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
