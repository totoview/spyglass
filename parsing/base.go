package parsing

import (
	"fmt"
)

type Parser interface {
	Parse([]byte)
}

func New(dataType string) (Parser, error) {
	switch dataType {
	case "line":
		return &LineParser{}, nil
	}
	return nil, fmt.Errorf("Unknown data type %s", dataType)
}
