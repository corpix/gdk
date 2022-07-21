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
	all := true
	for _, key := range MapKeys(ValueOf(m1)) {
		_, all = m1[key]
		if !all {
			break
		}
	}
	assert.True(t, all)
}

func TestMapSortedKeys(t *testing.T) {
	m1 := map[string]struct{}{
		"hello": {},
		"world": {},
		"!":     {},
	}
	assert.Equal(t, []string{"!", "hello", "world"}, MapSortedKeys(ValueOf(m1)))
}
