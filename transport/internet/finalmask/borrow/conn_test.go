package borrow

import (
	"bytes"
	"io"
	gonet "net"
	"testing"
	"time"
)

func newPair(t *testing.T, bb []byte) (client *borrowConn, server *borrowConn) {
	t.Helper()
	c1, c2 := gonet.Pipe()
	cfg := &Config{BorrowBytes: bb}
	cl, err := NewConnClient(cfg, c1, false)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := NewConnServer(cfg, c2, true)
	if err != nil {
		t.Fatal(err)
	}
	return cl.(*borrowConn), sv.(*borrowConn)
}

func readAll(t *testing.T, conn *borrowConn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	return buf
}

func TestBorrowTransformsFirstTwoClientWrites(t *testing.T) {
	bb := []byte{0x00, 0x16}
	client, server := newPair(t, bb)

	go func() {
		if _, err := client.Write([]byte{0x34, 0x56}); err != nil {
			t.Error(err)
		}
	}()
	if got := readAll(t, server, 4); !bytes.Equal(got, []byte{0x34, 0x56, 0x00, 0x16}) {
		t.Fatalf("first write: server got %x", got)
	}

	go func() {
		if _, err := client.Write([]byte{0x00, 0x16, 0x67, 0x89, 0x87}); err != nil {
			t.Error(err)
		}
	}()
	if got := readAll(t, server, 3); !bytes.Equal(got, []byte{0x67, 0x89, 0x87}) {
		t.Fatalf("second write: server got %x", got)
	}

	// Third client write passes untouched.
	go func() {
		if _, err := client.Write([]byte{0xaa, 0xbb}); err != nil {
			t.Error(err)
		}
	}()
	if got := readAll(t, server, 2); !bytes.Equal(got, []byte{0xaa, 0xbb}) {
		t.Fatalf("third write: server got %x", got)
	}

	// Received data (server-to-client from the client's view) passes Read
	// untouched: it is never modified, only the sender's writes are.
	go func() {
		if _, err := server.Conn.Write([]byte{0x00, 0x16, 0xff}); err != nil {
			t.Error(err)
		}
	}()
	if got := readAll(t, client, 3); !bytes.Equal(got, []byte{0x00, 0x16, 0xff}) {
		t.Fatalf("server data: client got %x", got)
	}
}

// The mask applies to whichever side it wraps: on a server it transforms the
// server's own (server-to-client) writes the same way, mirroring fragment.
func TestBorrowTransformsFirstTwoServerWrites(t *testing.T) {
	bb := []byte{0x00, 0x16}
	client, server := newPair(t, bb)

	go func() {
		if _, err := server.Write([]byte{0x34, 0x56}); err != nil {
			t.Error(err)
		}
	}()
	if got := readAll(t, client, 4); !bytes.Equal(got, []byte{0x34, 0x56, 0x00, 0x16}) {
		t.Fatalf("first server write: client got %x", got)
	}

	go func() {
		if _, err := server.Write([]byte{0x00, 0x16, 0x67}); err != nil {
			t.Error(err)
		}
	}()
	if got := readAll(t, client, 1); !bytes.Equal(got, []byte{0x67}) {
		t.Fatalf("second server write: client got %x", got)
	}
}

func TestBorrowSecondWriteMismatchErrors(t *testing.T) {
	bb := []byte{0x00, 0x16}
	client, server := newPair(t, bb)

	go func() {
		if _, err := client.Write([]byte{0x34, 0x56}); err != nil {
			t.Error(err)
		}
	}()
	readAll(t, server, 4) // first write: 2 bytes + 2 borrowed

	// Second write does not start with borrow bytes: must error, send nothing.
	if _, err := client.Write([]byte{0x99, 0x16, 0x67}); err == nil {
		t.Fatal("expected error for mismatched second write")
	}
}

func TestBorrowSecondWriteShorterThanBorrowBytes(t *testing.T) {
	bb := []byte{0x00, 0x16}
	client, server := newPair(t, bb)

	go func() {
		if _, err := client.Write([]byte{0x34, 0x56}); err != nil {
			t.Error(err)
		}
	}()
	readAll(t, server, 4)

	// Second packet (1 byte) is shorter than borrowBytes (2): must error.
	if _, err := client.Write([]byte{0x00}); err == nil {
		t.Fatal("expected error for second packet shorter than borrow bytes")
	}
}

func TestBorrowEmptyBytesPassThrough(t *testing.T) {
	client, server := newPair(t, nil)

	go func() {
		if _, err := client.Write([]byte{0x01, 0x02}); err != nil {
			t.Error(err)
		}
	}()
	if got := readAll(t, server, 2); !bytes.Equal(got, []byte{0x01, 0x02}) {
		t.Fatalf("empty borrow: server got %x", got)
	}
}
