package logger

import (
	"log"
	"os"
)

type NewCustomLogger struct {
	debug *log.Logger
	info  *log.Logger
	warn  *log.Logger
	error *log.Logger
}

var Logger *NewCustomLogger

func init() {
	Logger = &NewCustomLogger{
		debug: log.New(os.Stdout, "DEBUG: ", log.LstdFlags),
		info:  log.New(os.Stdout, "INFO: ", log.LstdFlags),
		warn:  log.New(os.Stdout, "WARN: ", log.LstdFlags),
		error: log.New(os.Stderr, "ERROR: ", log.LstdFlags),
	}
}

func Debug(v ...interface{}) {
	Logger.debug.Println(v...)
}

func Info(v ...interface{}) {
	Logger.info.Println(v...)
}

func Warn(v ...interface{}) {
	Logger.warn.Println(v...)
}

func Error(v ...interface{}) {
	Logger.error.Println(v...)
}

func Debugf(format string, v ...interface{}) {
	Logger.debug.Printf(format, v...)
}

func Infof(format string, v ...interface{}) {
	Logger.info.Printf(format, v...)
}

func Warnf(format string, v ...interface{}) {
	Logger.warn.Printf(format, v...)
}

func Errorf(format string, v ...interface{}) {
	Logger.error.Printf(format, v...)
}
