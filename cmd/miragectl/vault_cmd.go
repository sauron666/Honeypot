package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sauron666/Honeypot/internal/store"
	"github.com/sauron666/Honeypot/internal/vault"
)

// vaultCmd signs an evidence chain head so a third party can trust it, and
// verifies a seal. The internal hash chain proves the evidence is unaltered;
// the seal proves it came from this deployment, and an optional RFC 3161
// timestamp proves when it existed -- the two questions a court asks that a
// self-produced log cannot answer.
func vaultCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: miragectl vault seal|verify [flags]")
	}
	switch args[0] {
	case "seal":
		return vaultSeal(args[1:])
	case "verify":
		return vaultVerify(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q (seal | verify)", args[0])
	}
}

func vaultSeal(args []string) error {
	fs := flag.NewFlagSet("vault seal", flag.ExitOnError)
	file := fs.String("file", "data/evidence.jsonl", "evidence file to seal")
	keyPath := fs.String("key", "data/vault.key", "signing key (created if absent)")
	out := fs.String("out", "", "write the seal here (default: <file>.seal.json)")
	tsa := fs.String("tsa", "", "optional RFC 3161 TSA URL to timestamp the head (e.g. https://freetsa.org/tsr)")
	tenant := fs.String("tenant", "default", "tenant id to record in the seal")
	site := fs.String("site", "default", "site id to record in the seal")
	fs.Parse(args)

	st, err := store.OpenFile(*file, store.FileOptions{MemoryWindow: 10, SyncEvery: 0})
	if err != nil {
		return err
	}
	defer st.Close()
	// Verify the chain before sealing: signing a broken chain would attest to
	// evidence that does not hold together, which is worse than not sealing.
	if err := st.Verify(context.Background()); err != nil {
		return fmt.Errorf("refusing to seal: the evidence chain does not verify: %w", err)
	}
	seq, hash := st.Head()

	var kp *vault.Keypair
	if _, statErr := os.Stat(*keyPath); statErr == nil {
		if kp, err = vault.LoadKey(*keyPath); err != nil {
			return err
		}
	} else {
		if kp, err = vault.GenerateKeypair(); err != nil {
			return err
		}
		if err := kp.SaveKey(*keyPath); err != nil {
			return err
		}
		fmt.Printf("created a new signing key: %s (fingerprint %s)\n",
			*keyPath, vault.Fingerprint(kp.Public))
		fmt.Println("keep this key safe and back it up: it is this deployment's evidence identity.")
	}

	seal := kp.SealHead(*tenant, *site, seq, hash, time.Now())

	if *tsa != "" {
		digest := seal.HeadDigest()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		token, terr := vault.FetchTimestamp(ctx, *tsa, digest)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "warning: could not obtain an RFC 3161 timestamp (%v); "+
				"the seal is still signed, just not independently dated\n", terr)
		} else {
			seal.Timestamp = fmt.Sprintf("%x", token)
			seal.TimestampAuthority = *tsa
			if gt, gErr := vault.ExtractGenTime(token); gErr == nil {
				fmt.Printf("RFC 3161 timestamp obtained: the head existed at %s (per %s)\n",
					gt.Format(time.RFC3339), *tsa)
			}
		}
	}

	sealPath := *out
	if sealPath == "" {
		sealPath = *file + ".seal.json"
	}
	if err := vault.WriteSeal(seal, sealPath); err != nil {
		return err
	}
	hashShort := hash
	if len(hashShort) > 16 {
		hashShort = hashShort[:16]
	}
	fmt.Printf("sealed head seq=%d hash=%s\n", seq, hashShort)
	fmt.Printf("seal written to %s (public key fingerprint %s)\n",
		sealPath, vault.Fingerprint(kp.Public))
	fmt.Printf("verify it with: miragectl vault verify -seal %s -file %s\n", sealPath, *file)
	return nil
}

func vaultVerify(args []string) error {
	fs := flag.NewFlagSet("vault verify", flag.ExitOnError)
	sealPath := fs.String("seal", "", "the seal to verify (required)")
	file := fs.String("file", "", "optional evidence file to check the head against")
	fs.Parse(args)
	if *sealPath == "" {
		return fmt.Errorf("-seal is required")
	}

	seal, err := vault.ReadSeal(*sealPath)
	if err != nil {
		return err
	}
	if err := vault.VerifySeal(seal); err != nil {
		return err
	}
	fmt.Printf("seal signature: OK (from key %s)\n", vault.FingerprintHex(seal.PublicKey))
	fmt.Printf("attests: tenant=%s site=%s head seq=%d hash=%s, sealed %s\n",
		seal.TenantID, seal.SiteID, seal.HeadSeq, seal.HeadHash,
		seal.SealedAt.Format(time.RFC3339))

	if seal.Timestamp != "" {
		fmt.Printf("RFC 3161 timestamp present from %s\n", seal.TimestampAuthority)
		fmt.Println("  verify the TSA signature independently with: openssl ts -verify")
	}

	if *file != "" {
		st, err := store.OpenFile(*file, store.FileOptions{MemoryWindow: 10, SyncEvery: 0})
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.Verify(context.Background()); err != nil {
			return fmt.Errorf("the evidence file's own chain does not verify: %w", err)
		}
		seq, hash := st.Head()
		if seq != seal.HeadSeq || hash != seal.HeadHash {
			return fmt.Errorf("MISMATCH: the seal attests seq=%d hash=%s but the file's head is "+
				"seq=%d hash=%s (the file changed after sealing, or the seal is for another file)",
				seal.HeadSeq, seal.HeadHash, seq, hash)
		}
		fmt.Printf("evidence file: chain verifies and its head matches the seal (seq=%d)\n", seq)
	}
	fmt.Println("VERIFIED")
	return nil
}
