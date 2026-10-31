package app

import "testing"

func FuzzDoctorValidation(f *testing.F) {
	for _, value := range []string{"https://example.com", "127.0.0.1:80", "[::1]:443", "http://user:secret@example.com", "https://[::1]:99999", "\x00\n"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) { _ = validateDoctorTarget(value) })
}
