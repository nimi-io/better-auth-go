package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
)

func secretCommand() *command {
	return &command{
		name: "secret",
		desc: "Generate a random secret for BETTER_AUTH_SECRET",
		run:  (*runner).secret,
	}
}

// secret prints 32 random bytes as hex (crypto.randomBytes(32).toString("hex")).
func (r *runner) secret(*flag.FlagSet) int {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return r.fail(err)
	}
	fmt.Fprintf(r.stdout, "\nAdd the following to your .env file:\n%s%s\n", r.st.gray("# Auth Secret"), r.st.green("\nBETTER_AUTH_SECRET="+hex.EncodeToString(b)))
	return 0
}
