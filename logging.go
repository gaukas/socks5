package socks5

// Added this interface so the package remains 0-dependency
// and allows the user to import their own logger when needed.
//
// It is recommended to use zap.SugaredLogger as it fits the interface
// and is efficient.
type Logger interface {
	Debug(args ...any)
	Debugf(format string, args ...any)
	Info(args ...any)
	Infof(format string, args ...any)
	Warn(args ...any)
	Warnf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// noLogger is a no-op logger
type noLogger struct{}

func (*noLogger) Debug(_ ...any) {
}

func (*noLogger) Debugf(_ string, _ ...any) {
}

func (*noLogger) Info(_ ...any) {
}

func (*noLogger) Infof(_ string, _ ...any) {
}

func (*noLogger) Warn(_ ...any) {
}

func (*noLogger) Warnf(_ string, _ ...any) {
}

func (*noLogger) Error(_ ...any) {
}

func (*noLogger) Errorf(_ string, _ ...any) {
}

func (*noLogger) Fatal(_ ...any) {
}

func (*noLogger) Fatalf(_ string, _ ...any) {
}

// type guard
var _ Logger = (*noLogger)(nil)
