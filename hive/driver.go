package hive2

import (
	"context"
	"database/sql"
	"database/sql/driver"
)

func init() {
	sql.Register("hive2", &HiveDriver{})
}

type HiveDriver struct{}

func (h HiveDriver) Open(uri string) (driver.Conn, error) {
	params, err := ParseUrl(uri)
	if err != nil {
		return nil, err
	}
	c := &connector{
		params: params,
	}
	return c.Connect(context.Background())
}

func (h HiveDriver) OpenConnector(uri string) (driver.Connector, error) {
	params, err := ParseUrl(uri)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &connector{
		params: params,
	}, nil
}
