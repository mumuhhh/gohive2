package hive2

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/mumuhhh/gohive2/hive/rpc/tcliservice"
	"strconv"
)

type hiveStmt struct {
	hc         *hiveConn
	sql        string
	stmtHandle *tcliservice.TOperationHandle
	fetchSize  int

	isCancelled, isQueryClosed, isExecuteStatementFailed, isOperationComplete bool
}

func (hs *hiveStmt) closeClientOperation() error {
	if hs.stmtHandle != nil {
		closeReq := tcliservice.NewTCloseOperationReq()
		closeReq.OperationHandle = hs.stmtHandle
		closeResp, err := hs.hc.client.CloseOperation(context.Background(), closeReq)
		if err != nil {
			return err
		}
		if !verifySuccessWithInfo(closeResp.GetStatus()) {
			return fmt.Errorf("Error from server: %s ", closeResp.Status.String())
		}
	}
	hs.isQueryClosed = true
	hs.isExecuteStatementFailed = false
	hs.stmtHandle = nil
	return nil
}

func (hs *hiveStmt) Close() error {
	return hs.closeClientOperation()
}

func (hs *hiveStmt) initFlags() {
	hs.isCancelled = false
	hs.isQueryClosed = false
	hs.isExecuteStatementFailed = false
	hs.isOperationComplete = false
}

func (hs *hiveStmt) runAsyncOnServer(sql string) error {
	if err := hs.closeClientOperation(); err != nil {
		return err
	}
	hs.initFlags()
	execReq := tcliservice.NewTExecuteStatementReq()
	execReq.SessionHandle = hs.hc.sessHandle
	execReq.Statement = sql
	execReq.RunAsync = true
	execResp, err := hs.hc.client.ExecuteStatement(hs.hc.ctx, execReq)
	if err != nil {
		hs.isExecuteStatementFailed = true
		return err
	}
	if !verifySuccessWithInfo(execResp.GetStatus()) {
		return fmt.Errorf("Error from server: %s ", execResp.Status.String())
	}
	hs.stmtHandle = execResp.OperationHandle
	hs.isExecuteStatementFailed = false
	return nil
}

func (hs *hiveStmt) waitForOperationToComplete() (err error) {
	statusReq := tcliservice.NewTGetOperationStatusReq()
	statusReq.OperationHandle = hs.stmtHandle

	var statusResp *tcliservice.TGetOperationStatusResp
	for !hs.isOperationComplete {
		statusResp, err = hs.hc.client.GetOperationStatus(hs.hc.ctx, statusReq)
		if err != nil {
			return err
		}
		if !verifySuccessWithInfo(statusResp.GetStatus()) {
			return fmt.Errorf("Error from server: %s ", statusResp.Status.String())
		}
		if statusResp.IsSetOperationState() {
			switch statusResp.GetOperationState() {
			case tcliservice.TOperationState_CLOSED_STATE:
				fallthrough
			case tcliservice.TOperationState_FINISHED_STATE:
				hs.isOperationComplete = true
			case tcliservice.TOperationState_CANCELED_STATE:
				return errors.New("Query was cancelled ")
			case tcliservice.TOperationState_TIMEDOUT_STATE:
				return errors.New("Query timed out after \" + queryTimeout + \" seconds ")
			case tcliservice.TOperationState_ERROR_STATE:
				return errors.New("msg: " + statusResp.GetErrorMessage() +
					", sqlState:" + statusResp.GetSqlState() +
					", errorCode:" + strconv.Itoa(int(statusResp.GetErrorCode())))

			case tcliservice.TOperationState_UKNOWN_STATE:
				return errors.New("Unknown query HY000 ")
			default:

			}
		}
	}
	return nil
}

func (hs *hiveStmt) NumInput() int {
	return 0
}

func (hs *hiveStmt) Exec(args []driver.Value) (driver.Result, error) {
	_, err := hs.Query(args)
	if err != nil {
		return nil, err
	}
	return driver.ResultNoRows, nil
}

func (hs *hiveStmt) Query(args []driver.Value) (driver.Rows, error) {
	err := hs.runAsyncOnServer(hs.sql)
	if err != nil {
		return nil, err
	}
	hr := &hiveRows{
		hiveStmt: hs,
	}
	err = hr.retrieveSchema()
	if err != nil {
		return nil, err
	}
	return hr, nil
}
