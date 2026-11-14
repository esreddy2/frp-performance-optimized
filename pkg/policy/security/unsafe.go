package security

import "context"

const (
	TokenSourceExec = "TokenSourceExec"
)

var (
	ClientUnsafeFeatures = []string{
		TokenSourceExec,
	}

	ServerUnsafeFeatures = []string{
		TokenSourceExec,
	}
)

type UnsafeFeatures struct {
	features map[string]bool
}

func NewUnsafeFeatures(allowed []string) *UnsafeFeatures {
	features := make(map[string]bool)
	for _, f := range allowed {
		features[f] = true
	}
	return &UnsafeFeatures{features: features}
}

func (u *UnsafeFeatures) IsEnabled(feature string) bool {
	if u == nil {
		return false
	}
	return u.features[feature]
}

type contextKey struct{}

func WithUnsafeFeatures(ctx context.Context, u *UnsafeFeatures) context.Context {
	return context.WithValue(ctx, contextKey{}, u)
}

func FromContext(ctx context.Context) *UnsafeFeatures {
	if ctx == nil {
		return nil
	}
	if u, ok := ctx.Value(contextKey{}).(*UnsafeFeatures); ok {
		return u
	}
	return nil
}
