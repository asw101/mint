package main

import (
	"os"
	"path/filepath"
	"testing"
)

// configHome points os.UserConfigDir at a temporary directory on every
// platform: Linux reads XDG_CONFIG_HOME and falls back to $HOME/.config, macOS
// reads $HOME only, so setting both covers each.
func configHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	return dir
}

func TestLegacyName(t *testing.T) {
	for name, want := range map[string]string{
		"mint":        "tsapp",
		"mint-client": "tsapp-client",
	} {
		if got := legacyName(name); got != want {
			t.Errorf("legacyName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestDefaultStateDirPrefersMint(t *testing.T) {
	config := configHome(t)
	// Both present: the new name wins, so a migrated host never silently
	// starts reading the directory it just moved away from.
	mustMkdir(t, filepath.Join(config, "mint"))
	mustMkdir(t, filepath.Join(config, "tsapp"))

	if got, want := defaultStateDir("mint"), filepath.Join(config, "mint"); got != want {
		t.Errorf("defaultStateDir = %q, want %q", got, want)
	}
}

func TestDefaultStateDirFallsBackToLegacy(t *testing.T) {
	config := configHome(t)
	// Only the tsapp directory exists: an unmigrated host upgrading in place.
	// Answering with the mint path here would cost the node its identity and
	// the daemon every approval it holds.
	mustMkdir(t, filepath.Join(config, "tsapp-client"))

	if got, want := defaultStateDir("mint-client"), filepath.Join(config, "tsapp-client"); got != want {
		t.Errorf("defaultStateDir = %q, want %q", got, want)
	}
}

func TestDefaultStateDirDefaultsToMint(t *testing.T) {
	config := configHome(t)
	// Neither exists: a fresh install has nothing to be compatible with.
	if got, want := defaultStateDir("mint"), filepath.Join(config, "mint"); got != want {
		t.Errorf("defaultStateDir = %q, want %q", got, want)
	}
}

func TestEnvOrLegacy(t *testing.T) {
	t.Run("new wins", func(t *testing.T) {
		t.Setenv("MINT_SERVER", "http://new:8080")
		t.Setenv("TSAPP_SERVER", "http://old:8080")
		if got := envOrLegacy("MINT_SERVER", defaultServer); got != "http://new:8080" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("legacy honoured", func(t *testing.T) {
		t.Setenv("MINT_SERVER", "")
		t.Setenv("TSAPP_SERVER", "http://old:8080")
		if got := envOrLegacy("MINT_SERVER", defaultServer); got != "http://old:8080" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("neither set", func(t *testing.T) {
		t.Setenv("MINT_SERVER", "")
		t.Setenv("TSAPP_SERVER", "")
		if got := envOrLegacy("MINT_SERVER", defaultServer); got != defaultServer {
			t.Errorf("got %q", got)
		}
	})
}

func TestLegacyEnvNames(t *testing.T) {
	for key, want := range map[string]string{
		"MINT_SERVER":       "TSAPP_SERVER",
		"MINT_STATE_DIR":    "TSAPP_STATE_DIR",
		"MINT_SOCKET_GROUP": "TSAPP_SOCKET_GROUP",
	} {
		if got := legacyPrefix2Env(key); got != want {
			t.Errorf("legacyPrefix2Env(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"tsapp.tail1234.ts.net.": "tsapp",
		"mint.tail1234.ts.net":   "mint",
		"mint":                   "mint",
		"":                       "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMigrateStateDir(t *testing.T) {
	config := configHome(t)
	legacy := filepath.Join(config, "tsapp")
	mustMkdir(t, legacy)
	// A file stands in for the tsnet node key: the point of a move rather than
	// a fresh directory is that what is inside survives.
	if err := os.WriteFile(filepath.Join(legacy, "approvals.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	from, to, err := migrateStateDir("mint")
	if err != nil {
		t.Fatalf("migrateStateDir: %v", err)
	}
	if from != legacy || to != filepath.Join(config, "mint") {
		t.Fatalf("migrateStateDir returned %q -> %q", from, to)
	}
	if _, err := os.Stat(filepath.Join(to, "approvals.json")); err != nil {
		t.Errorf("contents did not survive the move: %v", err)
	}
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Errorf("legacy directory still present: %v", err)
	}
}

func TestMigrateStateDirRefusesToClobber(t *testing.T) {
	config := configHome(t)
	mustMkdir(t, filepath.Join(config, "tsapp"))
	mustMkdir(t, filepath.Join(config, "mint"))

	if _, _, err := migrateStateDir("mint"); err == nil {
		t.Fatal("migrating over an existing mint directory should fail")
	}
}

func TestMigrateStateDirNothingToDo(t *testing.T) {
	configHome(t)
	_, _, err := migrateStateDir("mint")
	if !os.IsNotExist(err) {
		t.Fatalf("want a not-exist error, got %v", err)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}
