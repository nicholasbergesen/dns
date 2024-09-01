package log

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Log struct {
	FileName       string
	ShowIncConsole bool
}

func (l *Log) FormatDate() {
	l.FileName = strings.Replace(l.FileName, "{date}", time.Now().Format("2006-01-02"), -1)
}

func (l *Log) Write(text string, a ...any) {
	fi, err := os.OpenFile(l.FileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open file %s\n", l.FileName)
		return
	}
	defer fi.Close()
	renderedText := fmt.Sprintf(text, a...)

	_, err = fi.Write([]byte(renderedText))
	if err != nil {
		fmt.Printf("Failed to write to %s\n", l.FileName)
	}
	if l.ShowIncConsole {
		fmt.Printf(text, a...)
	}
}
