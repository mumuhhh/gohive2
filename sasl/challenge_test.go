package sasl_test

import (
	"regexp"
	"testing"
)

func TestREG(t *testing.T) {
	var challengeRegexp = regexp.MustCompile(",?([a-zA-Z0-9]+)=(\"([^\"]+)\"|([^,]+)),?")
	submatch := challengeRegexp.FindAllSubmatch([]byte(`ax="vcx,fgfdg"`), -1)
	for _, m := range submatch {
		t.Log(string(m[0]), string(m[1]), string(m[2]), string(m[3]), string(m[4]))
	}

}
