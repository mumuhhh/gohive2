package hive2

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/apache/thrift/lib/go/thrift"

	"github.com/mumuhhh/gohive2/hive/rpc/tcliservice"
)

type hiveConn struct {
	transport  thrift.TTransport
	client     *tcliservice.TCLIServiceClient
	sessHandle *tcliservice.TSessionHandle
	protocol   tcliservice.TProtocolVersion
	ctx        context.Context
	fetchSize  int64
	params     *ConnParams
}

func (hc *hiveConn) Prepare(query string) (driver.Stmt, error) {
	hcStmt := &hiveStmt{
		hc:  hc,
		sql: query,
	}
	return hcStmt, nil
}

func (hc *hiveConn) Close() error {
	closeReq := tcliservice.NewTCloseSessionReq()
	closeReq.SessionHandle = hc.sessHandle
	_, err := hc.client.CloseSession(hc.ctx, closeReq)
	if hc.transport != nil {
		if err := hc.transport.Close(); err != nil {
			return fmt.Errorf("error closing socket: ")
		}
	}
	return err
}

func (hc *hiveConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not support")
}

var _ driver.Conn = (*hiveConn)(nil)
