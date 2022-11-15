package hive2

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/mumuhhh/gohive2/hive/rpc/tcliservice"
)

func verifySuccess(p *tcliservice.TStatus, withInfo bool) bool {
	status := p.GetStatusCode()
	return status == tcliservice.TStatusCode_SUCCESS_STATUS || (withInfo && status == tcliservice.TStatusCode_SUCCESS_WITH_INFO_STATUS)
}

func verifySuccessWithInfo(p *tcliservice.TStatus) bool {
	return verifySuccess(p, true)
}

type ConnParams struct {
	DBName        string
	JdbcUriString string
	Addresses     []string
	HiveConf      map[string]string
	HiveVar       map[string]string
	SessionVar    map[string]string
}

func ParseUrl(uri string) (*ConnParams, error) {
	p := &ConnParams{
		DBName:     "default",
		SessionVar: map[string]string{},
		HiveVar:    map[string]string{},
		HiveConf:   map[string]string{},
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	p.Addresses = strings.Split(u.Host, ",")
	pattern := regexp.MustCompile("([^;]*)=([^;]*)[;]?")
	sessVars := u.Path
	if sessVars != "" {
		// removing leading '/' returned by getPath()
		sessVars = sessVars[1:]
		if !strings.Contains(sessVars, ";") {
			p.DBName = sessVars
		} else {
			// we have dbname followed by session parameters
			p.DBName = sessVars[0:strings.Index(sessVars, ";")]
			sessVars = sessVars[strings.Index(sessVars, ";")+1:]
			if sessVars != "" {
				sessMatch := pattern.FindAllStringSubmatch(sessVars, -1)
				for _, m := range sessMatch {
					p.SessionVar[m[1]] = m[2]
				}
			}
		}
	}

	confStr := u.RawQuery
	if confStr != "" {
		confMatch := pattern.FindAllStringSubmatch(confStr, -1)
		for _, m := range confMatch {
			p.HiveConf[m[1]] = m[2]
		}
	}

	varStr := u.Fragment
	if varStr != "" {
		varMatch := pattern.FindAllStringSubmatch(varStr, -1)
		for _, m := range varMatch {
			p.HiveVar[m[1]] = m[2]
		}
	}
	return p, nil
}
