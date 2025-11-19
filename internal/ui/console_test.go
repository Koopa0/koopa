package ui

import (
	"bytes"
	"io"
	"testing"
)

func TestConsole_Print(t *testing.T) {
	var out bytes.Buffer
	console := NewConsole(nil, &out)

	console.Print("Hello", " ", "World")

	expected := "Hello World"
	if got := out.String(); got != expected {
		t.Errorf("Print() = %q, want %q", got, expected)
	}
}

func TestConsole_Println(t *testing.T) {
	var out bytes.Buffer
	console := NewConsole(nil, &out)

	console.Println("Hello", "World")

	expected := "Hello World\n"
	if got := out.String(); got != expected {
		t.Errorf("Println() = %q, want %q", got, expected)
	}
}

func TestConsole_Printf(t *testing.T) {
	var out bytes.Buffer
	console := NewConsole(nil, &out)

	console.Printf("Hello %s", "World")

	expected := "Hello World"
	if got := out.String(); got != expected {
		t.Errorf("Printf() = %q, want %q", got, expected)
	}
}

func TestConsole_Scan(t *testing.T) {
	input := "line1\nline2"
	in := bytes.NewBufferString(input)
	console := NewConsole(in, nil)

	// First line
	if !console.Scan() {
		t.Fatal("Scan() returned false, want true")
	}
	if got := console.Text(); got != "line1" {
		t.Errorf("Text() = %q, want %q", got, "line1")
	}

	// Second line
	if !console.Scan() {
		t.Fatal("Scan() returned false, want true")
	}
	if got := console.Text(); got != "line2" {
		t.Errorf("Text() = %q, want %q", got, "line2")
	}

	// EOF
	if console.Scan() {
		t.Error("Scan() returned true at EOF, want false")
	}
}

func TestConsole_Confirm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{"yes", "y\n", true, false},
		{"YES", "YES\n", true, false},
		{"no", "n\n", false, false},
		{"NO", "NO\n", false, false},
		{"retry", "invalid\ny\n", true, false},
		{"eof", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := bytes.NewBufferString(tt.input)
			var out bytes.Buffer
			console := NewConsole(in, &out)

			got, err := console.Confirm("Proceed?")

			if (err != nil) != tt.wantErr {
				t.Errorf("Confirm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Confirm() = %v, want %v", got, tt.want)
			}

			// Verify prompt was printed
			if !bytes.Contains(out.Bytes(), []byte("Proceed? [y/n]: ")) {
				t.Error("Confirm() did not print prompt")
			}
		})
	}
}

func TestConsole_Stream(t *testing.T) {
	var out bytes.Buffer
	console := NewConsole(nil, &out)

	console.Stream("chunk1")
	console.Stream("chunk2")

	expected := "chunk1chunk2"
	if got := out.String(); got != expected {
		t.Errorf("Stream() output = %q, want %q", got, expected)
	}
}

// TestConsole_Confirm_EOF verifies behavior when EOF is encountered during retry
func TestConsole_Confirm_EOF(t *testing.T) {
	in := bytes.NewBufferString("invalid\n") // No newline after invalid, so next scan hits EOF
	var out bytes.Buffer
	console := NewConsole(in, &out)

	_, err := console.Confirm("Proceed?")
	if err != io.EOF {
		t.Errorf("Confirm() error = %v, want %v", err, io.EOF)
	}
}
