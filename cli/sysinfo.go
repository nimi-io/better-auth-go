package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// systemInfo is getSystemInfo (os.platform(), os.arch(), os.version(), ...).
func systemInfo() *object {
	o := newObject()
	o.set("platform", runtime.GOOS)
	o.set("arch", runtime.GOARCH)
	o.set("version", orUnknown(osVersion()))
	o.set("release", orUnknown(osRelease()))
	o.set("cpuCount", runtime.NumCPU())
	o.set("cpuModel", orUnknown(cpuModel()))
	o.set("totalMemory", formatGB(totalMemory()))
	o.set("freeMemory", formatGB(freeMemory()))
	return o
}

func orUnknown(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

func formatGB(bytes uint64) string {
	if bytes == 0 {
		return "Unknown"
	}
	return fmt.Sprintf("%.2f GB", float64(bytes)/1024/1024/1024)
}

// command output with a short timeout; "" on any failure.
func output(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func osVersion() string {
	if runtime.GOOS == "windows" {
		return output("cmd", "/c", "ver")
	}
	return output("uname", "-v")
}

func osRelease() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return output("uname", "-r")
}

func procField(file, key string) string {
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func cpuModel() string {
	switch runtime.GOOS {
	case "darwin":
		return output("sysctl", "-n", "machdep.cpu.brand_string")
	case "linux":
		return procField("/proc/cpuinfo", "model name")
	}
	return ""
}

func meminfoBytes(key string) uint64 {
	v := strings.TrimSuffix(procField("/proc/meminfo", key), " kB")
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0
	}
	return n * 1024
}

func totalMemory() uint64 {
	switch runtime.GOOS {
	case "darwin", "freebsd":
		n, _ := strconv.ParseUint(output("sysctl", "-n", "hw.memsize"), 10, 64)
		if n == 0 {
			n, _ = strconv.ParseUint(output("sysctl", "-n", "hw.physmem"), 10, 64)
		}
		return n
	case "linux":
		return meminfoBytes("MemTotal")
	}
	return 0
}

var vmPageSize = regexp.MustCompile(`page size of (\d+) bytes`)

func freeMemory() uint64 {
	switch runtime.GOOS {
	case "darwin":
		out := output("vm_stat")
		m := vmPageSize.FindStringSubmatch(out)
		if m == nil {
			return 0
		}
		size, _ := strconv.ParseUint(m[1], 10, 64)
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Pages free" {
				pages, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), "."), 10, 64)
				return pages * size
			}
		}
	case "linux":
		return meminfoBytes("MemAvailable")
	}
	return 0
}
