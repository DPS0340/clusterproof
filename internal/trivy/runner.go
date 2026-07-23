package trivy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/DPS0340/clusterproof/internal/model"
)

// RunOptions bounds the optional Trivy subprocess.
type RunOptions struct {
	Executable     string
	Timeout        time.Duration
	MaxOutputBytes int64
	MaxErrorBytes  int64
}

// DefaultRunOptions returns safe subprocess limits.
func DefaultRunOptions() RunOptions {
	return RunOptions{
		Executable:     "trivy",
		Timeout:        5 * time.Minute,
		MaxOutputBytes: 100 << 20,
		MaxErrorBytes:  64 << 10,
	}
}

// FilesystemArgs returns a fixed Trivy filesystem command with a protected path.
func FilesystemArgs(path string) []string {
	return []string{
		"fs",
		"--no-progress",
		"--quiet",
		"--format", "json",
		"--scanners", "vuln,misconfig,secret",
		"--",
		path,
	}
}

// RunFilesystem explicitly invokes a local Trivy binary without a shell.
func RunFilesystem(ctx context.Context, path string, options RunOptions) ([]model.Finding, error) {
	if options.Executable == "" || options.Timeout <= 0 || options.MaxOutputBytes <= 0 || options.MaxErrorBytes <= 0 {
		return nil, errors.New("invalid Trivy run options")
	}
	executable, err := exec.LookPath(options.Executable)
	if err != nil {
		return nil, fmt.Errorf("find Trivy executable: %w", err)
	}

	runContext, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	stdout := newCappedBuffer(options.MaxOutputBytes)
	stderr := newCappedBuffer(options.MaxErrorBytes)
	command := exec.CommandContext(runContext, executable, FilesystemArgs(path)...)
	command.Stdout = stdout
	command.Stderr = stderr

	if err := command.Run(); err != nil {
		if errors.Is(runContext.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("trivy scan exceeded timeout of %s", options.Timeout)
		}
		return nil, fmt.Errorf("trivy scan failed: %w: %s", err, stderr.String())
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("trivy output exceeds limit of %d bytes", options.MaxOutputBytes)
	}
	return Parse(bytes.NewReader(stdout.Bytes()), options.MaxOutputBytes)
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	exceeded bool
}

func newCappedBuffer(limit int64) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining > 0 {
		toWrite := data
		if int64(len(toWrite)) > remaining {
			toWrite = toWrite[:remaining]
		}
		_, _ = b.buffer.Write(toWrite)
	}
	if int64(len(data)) > remaining {
		b.exceeded = true
	}
	return len(data), nil
}

func (b *cappedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *cappedBuffer) String() string {
	return cleanText(b.buffer.String())
}
