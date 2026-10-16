package ban

import (
	"context"
)

type Actor interface {
	Block(ctx context.Context, ip string, timeout string) error
	Init(ctx context.Context) error
	Exit(ctx context.Context) error
	Flush(ctx context.Context) error
}

func Methods() []string {
	return []string{"dummy", "ipset", "nft"}
}
