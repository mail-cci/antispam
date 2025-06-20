package milt

import (
	"context"
	"github.com/mail-cci/antispam/internal/config"
	_ "unsafe"
)

//go:linkname spfTxtLookup github.com/mail-cci/antispam/internal/spf.txtLookup
var spfTxtLookup func(ctx context.Context, domain string) ([]string, uint32, error)

//go:linkname spfCfg github.com/mail-cci/antispam/internal/spf.cfg
var spfCfg *config.Config

func setTxtLookup(fn func(ctx context.Context, domain string) ([]string, uint32, error)) {
	spfTxtLookup = fn
}
