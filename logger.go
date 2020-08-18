package gouxp

type Logger interface {
	Fatal(str string)
	Fatalf(format string, v ...interface{})
	Error(str string)
	Errorf(format string, v ...interface{})
	Warn(str string)
	Warnf(format string, v ...interface{})
	Info(str string)
	Infof(format string, v ...interface{})
	Debug(str string)
	Debugf(format string, v ...interface{})
}
