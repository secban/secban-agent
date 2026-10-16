package banloader

import (
	"fmt"

	"gitlab.com/secban/secban-agent/ban"
	"gitlab.com/secban/secban-agent/ban/dummy"
	"gitlab.com/secban/secban-agent/ban/ipset"
	"gitlab.com/secban/secban-agent/ban/nft"
)

func Load(name string) (ban.Actor, error) { //nolint: ireturn // It's just a convenience wrapper.
	switch name {
	case "dummy":
		return dummy.New(), nil
	case "ipset":
		return ipset.New(), nil
	case "nft":
		return nft.New(), nil
	}

	return nil, fmt.Errorf("unknown ban method: %s", name)
}
