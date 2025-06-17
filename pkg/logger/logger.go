package logger

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type LogConfig struct {
	Level         string
	FilePath      string
	MaxSizeMB     int
	MaxBackups    int
	MaxAgeDays    int
	ConsoleOutput bool
}

var (
	globalLogger *zap.Logger
	atomicLevel  zap.AtomicLevel
)

func Init(config LogConfig) (*zap.Logger, error) {
	if globalLogger != nil {
		return globalLogger, nil
	}

	atomicLevel = zap.NewAtomicLevel()
	if err := atomicLevel.UnmarshalText([]byte(config.Level)); err != nil {
		return nil, err
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout(time.RFC3339),
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var cores []zapcore.Core

	if config.FilePath != "" {
		fileWriter := zapcore.AddSync(&lumberjack.Logger{
			Filename:   config.FilePath,
			MaxSize:    config.MaxSizeMB, // megabytes
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAgeDays, // days
			Compress:   true,
		})

		fileEncoder := zapcore.NewJSONEncoder(encoderConfig)
		fileCore := zapcore.NewCore(fileEncoder, fileWriter, atomicLevel)
		cores = append(cores, fileCore)
	}

	if config.ConsoleOutput {
		consoleEncoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05"),
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		})
		consoleCore := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), atomicLevel)
		cores = append(cores, consoleCore)
	}

	combinedCore := zapcore.NewTee(cores...)

	globalLogger = zap.New(combinedCore,
		zap.AddCaller(),
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	zap.ReplaceGlobals(globalLogger)

	return globalLogger, nil
}

func GetLogger() *zap.Logger {
	return globalLogger
}

func SetLevel(level string) error {
	return atomicLevel.UnmarshalText([]byte(level))
}

func Sync() error {
	return globalLogger.Sync()
}
