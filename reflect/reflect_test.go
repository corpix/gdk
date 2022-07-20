package reflect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapKeys(t *testing.T) {
	m1 := map[string]struct{}{
		"hello": {},
		"world": {},
		"!":     {},
	}
	assert.Equal(t, []string{"hello", "world", "!"}, MapKeys(ValueOf(m1)))
}

func TestMapSortedKeys(t *testing.T) {
	m1 := map[string]struct{}{
		"hello": {},
		"world": {},
		"!":     {},
	}
	assert.Equal(t, []string{"!", "hello", "world"}, MapSortedKeys(ValueOf(m1)))
}
