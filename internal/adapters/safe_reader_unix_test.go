//go:build unix

package adapters

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSafeReaderRejectsSpecialFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "config.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, "zero.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("config.fifo", filepath.Join(root, "fifo-link.json")); err != nil {
		t.Fatal(err)
	}
	reader := newReader(t, root)
	for name, want := range map[string]error{"config.fifo": ErrNotRegular, "fifo-link.json": ErrNotRegular, "zero.json": ErrUnsafePath} {
		if _, err := reader.ReadFile(name, MaxConfigFileBytes); !errors.Is(err, want) {
			t.Errorf("ReadFile(%q) error = %v, want %v", name, err, want)
		}
	}
	for _, name := range []string{"/dev/zero", filepath.Join(root, "config.fifo")} {
		if _, err := ReadLocal(name, MaxConfigFileBytes); !errors.Is(err, ErrNotRegular) {
			t.Errorf("ReadLocal(%q) error = %v, want ErrNotRegular", name, err)
		}
	}
}

// A concurrent swap of a parent directory for a symlink to the outside, or
// of the file for a FIFO, must neither leak outside content nor block.
func TestSafeReaderSwapRace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "settings.json"), "outside")
	dir := filepath.Join(root, "cfg")
	parked := filepath.Join(root, "parked")
	write(t, filepath.Join(dir, "settings.json"), "inside")
	reader := newReader(t, root)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fifo := filepath.Join(root, "fifo.tmp")
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.Rename(dir, parked); err != nil {
				continue
			}
			if i%2 == 0 {
				_ = os.Symlink(outside, dir)
			} else {
				_ = os.Mkdir(dir, 0o700)
				_ = syscall.Mkfifo(fifo, 0o600)
				_ = os.Rename(fifo, filepath.Join(dir, "settings.json"))
			}
			time.Sleep(time.Microsecond)
			_ = os.RemoveAll(dir)
			_ = os.Rename(parked, dir)
		}
	}()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		data, err := reader.ReadFile("cfg/settings.json", MaxConfigFileBytes)
		if err == nil && string(data) != "inside" {
			close(stop)
			wg.Wait()
			t.Fatalf("read %q through a swapped path", data)
		}
	}
	close(stop)
	wg.Wait()
}
