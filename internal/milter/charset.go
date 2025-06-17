package milt

import (
	"github.com/emersion/go-message"
	"golang.org/x/net/html/charset"
)

func init() {
	message.CharsetReader = charset.NewReaderLabel
}
