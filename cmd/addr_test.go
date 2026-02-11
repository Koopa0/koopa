package cmd

import "testing"

func TestValidateAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		// Valid addresses
		{name: "port only", addr: ":8080", wantErr: false},
		{name: "localhost", addr: "localhost:3400", wantErr: false},
		{name: "loopback", addr: "127.0.0.1:3400", wantErr: false},
		{name: "all interfaces", addr: "0.0.0.0:80", wantErr: false},
		{name: "ipv6 loopback", addr: "[::1]:8080", wantErr: false},
		{name: "port zero", addr: ":0", wantErr: false},
		{name: "port max", addr: ":65535", wantErr: false},
		{name: "hostname", addr: "myhost:9090", wantErr: false},

		// Invalid: bad format
		{name: "no port", addr: "localhost", wantErr: true},
		{name: "port alone", addr: "8080", wantErr: true},
		{name: "empty string", addr: "", wantErr: true},

		// Invalid: bad port
		{name: "port non-numeric", addr: ":abc", wantErr: true},
		{name: "port negative", addr: ":-1", wantErr: true},
		{name: "port too high", addr: ":65536", wantErr: true},
		{name: "port empty after colon", addr: "localhost:", wantErr: true},

		// Invalid: bad host
		{name: "host with space", addr: "my host:8080", wantErr: true},
		{name: "host with tab", addr: "my\thost:8080", wantErr: true},
		{name: "host with newline", addr: "my\nhost:8080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateAddr(tt.addr)
			if tt.wantErr && err == nil {
				t.Errorf("validateAddr(%q) = nil, want error", tt.addr)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateAddr(%q) = %v, want nil", tt.addr, err)
			}
		})
	}
}

func FuzzValidateAddr(f *testing.F) {
	f.Add(":8080")
	f.Add("localhost:3400")
	f.Add("127.0.0.1:80")
	f.Add("")
	f.Add("abc")
	f.Add(":0")
	f.Add(":99999")
	f.Add("[::1]:8080")
	f.Add("host with space:80")

	f.Fuzz(func(t *testing.T, addr string) {
		_ = validateAddr(addr) // must not panic
	})
}
