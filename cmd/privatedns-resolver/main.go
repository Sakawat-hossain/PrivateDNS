// Command privatedns-resolver runs the PrivateDNS filtering resolver.
//
// It serves DNS-over-TLS, DNS-over-HTTPS and plain DNS, identifying each tenant
// from the TLS SNI (or, on the unencrypted listener, from the source address)
// and applying that tenant's own policy before answering.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sakawat-hossain/PrivateDNS/resolver"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=v0.1.0"
var version = "dev"

func main() {
	var (
		configPath  = flag.String("config", "/etc/private-dns/config.json", "path to the configuration file")
		writeSample = flag.Bool("init", false, "write a starter configuration file and exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
		backupTo    = flag.String("backup", "", "write a consistent snapshot of the policy database to this path and exit")
		verifyPath  = flag.String("verify-backup", "", "check that a backup file is a usable database and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if *writeSample {
		if err := resolver.WriteSample(*configPath); err != nil {
			log.Fatalf("write sample config: %v", err)
		}
		fmt.Printf("wrote %s — edit it, then run without -init\n", *configPath)
		return
	}

	if *verifyPath != "" {
		schema, tenants, err := resolver.VerifyBackup(*verifyPath)
		if err != nil {
			log.Fatalf("backup is not usable: %v", err)
		}
		fmt.Printf("backup ok: schema version %d, %d tenants\n", schema, tenants)
		return
	}

	cfg, err := resolver.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if *backupTo != "" {
		if err := resolver.Backup(cfg.DBPath, *backupTo); err != nil {
			log.Fatalf("backup failed: %v", err)
		}
		schema, tenants, err := resolver.VerifyBackup(*backupTo)
		if err != nil {
			// Taking a backup and not checking it leaves an assumption, and
			// the moment it matters is the worst time to test it.
			log.Fatalf("backup written but unreadable: %v", err)
		}
		fmt.Printf("backup written to %s (schema %d, %d tenants)\n", *backupTo, schema, tenants)
		return
	}

	srv, err := resolver.New(cfg)
	if err != nil {
		log.Fatalf("start: %v", err)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("listener stopped: %v", err)
	}
	log.Print("shutting down")
}
