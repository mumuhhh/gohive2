package hive2

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"

	"github.com/apache/thrift/lib/go/thrift"

	"github.com/mumuhhh/gohive2/hive/rpc/tcliservice"
)

type rowSetFactory interface {
	hasNext() bool
	next() []interface{}
}

func (rs *rowBasedSet) toColumnValue(col *tcliservice.TColumnValue) interface{} {
	switch {
	case col.IsSetBoolVal():
		value := col.GetBoolVal().Value
		if value != nil {
			return *value
		}
		return value
	case col.IsSetByteVal():
		value := col.GetByteVal().Value
		if value != nil {
			return *value
		}
		return value
	case col.IsSetI16Val():
		value := col.GetI16Val().Value
		if value != nil {
			return *value
		}
		return value
	case col.IsSetI32Val():
		value := col.GetI32Val().Value
		if value != nil {
			return *value
		}
		return value
	case col.IsSetI64Val():
		value := col.GetI64Val().Value
		if value != nil {
			return *value
		}
		return value
	case col.IsSetDoubleVal():
		value := col.GetDoubleVal().Value
		if value != nil {
			return *value
		}
		return value
	case col.IsSetStringVal():
		value := col.GetStringVal().Value
		if value != nil {
			return *value
		}
		return value
	default:
		return nil
	}
}

type rowBasedSet struct {
	tRowSet *tcliservice.TRowSet
	offset  int
}

func (rs *rowBasedSet) hasNext() bool {
	return rs.offset < len(rs.tRowSet.Rows)
}

func (rs *rowBasedSet) next() []interface{} {
	vals := rs.tRowSet.Rows[rs.offset].GetColVals()
	var result []interface{}
	for i := 0; i < len(vals); i++ {
		result = append(result, rs.toColumnValue(vals[i]))
	}
	rs.offset++
	return result
}

type colBasedSet struct {
	tRowSet  *tcliservice.TRowSet
	types    []tcliservice.TTypeId
	rowCount int
	offset   int
}

func (rs *colBasedSet) init() error {
	ctx := context.Background()
	columnCount := int(rs.tRowSet.GetColumnCount())
	if rs.tRowSet.IsSetBinaryColumns() {
		log.Println("--------", columnCount)
		protocol := thrift.NewTCompactProtocolConf(thrift.NewStreamTransportR(bytes.NewBuffer(rs.tRowSet.GetBinaryColumns())), &thrift.TConfiguration{})
		rs.tRowSet.Columns = make([]*tcliservice.TColumn, columnCount)
		for i := 0; i < columnCount; i++ {
			column := &tcliservice.TColumn{}
			rs.tRowSet.Columns[i] = column
			err := column.Read(ctx, protocol)
			if err != nil {
				return err
			}
		}
	} else {
		columnCount = len(rs.tRowSet.GetColumns())
	}
	columns := rs.tRowSet.GetColumns()

	rs.types = make([]tcliservice.TTypeId, columnCount)
	for i, col := range columns {
		switch {
		case col.IsSetBoolVal():
			rs.types[i] = tcliservice.TTypeId_BOOLEAN_TYPE
			rs.rowCount = len(col.GetBoolVal().GetValues())
		case col.IsSetByteVal():
			rs.types[i] = tcliservice.TTypeId_TINYINT_TYPE
			rs.rowCount = len(col.GetByteVal().GetValues())
		case col.IsSetI16Val():
			rs.types[i] = tcliservice.TTypeId_SMALLINT_TYPE
			rs.rowCount = len(col.GetI16Val().GetValues())
		case col.IsSetI32Val():
			rs.types[i] = tcliservice.TTypeId_INT_TYPE
			rs.rowCount = len(col.GetI32Val().GetValues())
		case col.IsSetI64Val():
			rs.types[i] = tcliservice.TTypeId_BIGINT_TYPE
			rs.rowCount = len(col.GetI64Val().GetValues())
		case col.IsSetDoubleVal():
			rs.types[i] = tcliservice.TTypeId_DOUBLE_TYPE
			rs.rowCount = len(col.GetDoubleVal().GetValues())
		case col.IsSetBinaryVal():
			rs.types[i] = tcliservice.TTypeId_BINARY_TYPE
			rs.rowCount = len(col.GetBinaryVal().GetValues())
		case col.IsSetStringVal():
			rs.types[i] = tcliservice.TTypeId_STRING_TYPE
			rs.rowCount = len(col.GetStringVal().GetValues())
		default:
			return errors.New("invalid union object")
		}
	}
	return nil
}

func (rs *colBasedSet) getColumnIndex(col *tcliservice.TColumn, index int) interface{} {
	switch {
	case col.IsSetBoolVal():
		nulls := col.GetBoolVal().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetBoolVal().GetValues()
			return vars[index]
		}
	case col.IsSetByteVal():
		nulls := col.GetByteVal().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetByteVal().GetValues()
			return vars[index]
		}
	case col.IsSetI16Val():
		nulls := col.GetI16Val().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetI16Val().GetValues()
			return vars[index]
		}
	case col.IsSetI32Val():
		nulls := col.GetI32Val().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetI32Val().GetValues()
			return vars[index]
		}
	case col.IsSetI64Val():
		nulls := col.GetI64Val().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetI64Val().GetValues()
			return vars[index]
		}
	case col.IsSetDoubleVal():
		nulls := col.GetDoubleVal().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetDoubleVal().GetValues()
			return vars[index]
		}
	case col.IsSetBinaryVal():
		nulls := col.GetBinaryVal().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetBinaryVal().GetValues()
			return vars[index]
		}
	case col.IsSetStringVal():
		nulls := col.GetStringVal().GetNulls()
		if !rs.isNull(nulls, index) {
			vars := col.GetStringVal().GetValues()
			return vars[index]
		}
	}
	return nil
}

func (rs *colBasedSet) hasNext() bool {
	return rs.offset < rs.rowCount
}

func (rs *colBasedSet) isNull(nulls []byte, index int) bool {
	isNull := byte(0)
	if index/8 < len(nulls) {
		isNull = nulls[index/8] & MASK[index%8]
	}
	if isNull != 0 {
		return true
	}
	return false
}

var MASK = []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

func (rs *colBasedSet) next() []interface{} {
	var result []interface{}
	columns := rs.tRowSet.GetColumns()
	for _, column := range columns {
		value := rs.getColumnIndex(column, rs.offset)
		result = append(result, value)
	}
	rs.offset++
	return result
}

type hiveRows struct {
	hiveStmt    *hiveStmt
	columns     []*tcliservice.TColumnDesc
	columnNames []string
	fetchedRows rowSetFactory
	fetchFirst  bool
	rowsFetched int
}

func (rows *hiveRows) retrieveSchema() error {
	metadataReq := tcliservice.NewTGetResultSetMetadataReq()
	metadataReq.OperationHandle = rows.hiveStmt.stmtHandle
	metadataResp, err := rows.hiveStmt.hc.client.GetResultSetMetadata(rows.hiveStmt.hc.ctx, metadataReq)
	if err != nil {
		return err
	}
	if !verifySuccess(metadataResp.GetStatus(), false) {
		return fmt.Errorf("Error from server: %s ", metadataResp.Status.String())
	}
	schema := metadataResp.GetSchema()
	if schema == nil || schema.GetColumns() == nil {
		return nil
	}
	rows.columns = schema.GetColumns()
	for _, column := range rows.columns {
		rows.columnNames = append(rows.columnNames, column.ColumnName)
	}
	return nil
}

func (rows *hiveRows) Columns() []string {
	return rows.columnNames
}

func (rows *hiveRows) Close() error {
	return rows.hiveStmt.closeClientOperation()
}

func (rows *hiveRows) Next(dest []driver.Value) error {
	if err := rows.hiveStmt.waitForOperationToComplete(); err != nil {
		return err
	}
	orientation := tcliservice.TFetchOrientation_FETCH_NEXT
	if rows.fetchFirst {
		orientation = tcliservice.TFetchOrientation_FETCH_FIRST
		rows.fetchedRows = nil
		rows.fetchFirst = false
	}
	if rows.fetchedRows == nil || !rows.fetchedRows.hasNext() {
		fetchReq := tcliservice.NewTFetchResultsReq()
		fetchReq.OperationHandle = rows.hiveStmt.stmtHandle
		fetchReq.Orientation = orientation
		fetchReq.MaxRows = rows.hiveStmt.hc.fetchSize
		fetchResp, err := rows.hiveStmt.hc.client.FetchResults(rows.hiveStmt.hc.ctx, fetchReq)
		if err != nil {
			return err
		}
		if !verifySuccessWithInfo(fetchResp.GetStatus()) {
			return fmt.Errorf("Error from server: %s ", fetchResp.Status.String())
		}
		results := fetchResp.GetResults()
		if rows.hiveStmt.hc.protocol > tcliservice.TProtocolVersion_HIVE_CLI_SERVICE_PROTOCOL_V6 {
			rowSet := &colBasedSet{
				tRowSet: results,
				offset:  0,
			}
			if err := rowSet.init(); err != nil {
				return err
			}
			rows.fetchedRows = rowSet
		} else {
			rows.fetchedRows = &rowBasedSet{
				tRowSet: results,
				offset:  0,
			}
		}

	}

	if rows.fetchedRows.hasNext() {
		row := rows.fetchedRows.next()
		for i := 0; i < len(dest); i++ {
			dest[i] = row[i]
		}
	} else {
		return errors.New("no data")
	}

	rows.rowsFetched++

	return nil
}

func (rows *hiveRows) ColumnTypeDatabaseTypeName(index int) string {
	return tcliservice.TYPE_NAMES[rows.columns[index].TypeDesc.Types[0].PrimitiveEntry.Type]
}

func (rows *hiveRows) ColumnTypeLength(index int) (length int64, ok bool) {
	if rows.columns[index].TypeDesc.Types[0].PrimitiveEntry.IsSetTypeQualifiers() {
		tq := rows.columns[index].TypeDesc.Types[0].PrimitiveEntry.GetTypeQualifiers()
		switch rows.columns[index].TypeDesc.Types[0].PrimitiveEntry.Type {
		case tcliservice.TTypeId_CHAR_TYPE, tcliservice.TTypeId_VARCHAR_TYPE:
			v, ok := tq.Qualifiers[tcliservice.CHARACTER_MAXIMUM_LENGTH]
			if ok {
				return int64(v.GetI32Value()), ok
			}
		default:
		}
	}
	return 0, false
}

func (rows *hiveRows) ColumnTypePrecisionScale(index int) (precision, scale int64, ok bool) {
	if rows.columns[index].TypeDesc.Types[0].PrimitiveEntry.IsSetTypeQualifiers() {
		tq := rows.columns[index].TypeDesc.Types[0].PrimitiveEntry.GetTypeQualifiers()
		switch rows.columns[index].TypeDesc.Types[0].PrimitiveEntry.Type {
		case tcliservice.TTypeId_DECIMAL_TYPE:
			precisionT := tq.Qualifiers[tcliservice.PRECISION]
			if precisionT != nil {
				precision = int64(precisionT.GetI32Value())
			} else {
				precision = 10
			}
			scaleT := tq.Qualifiers[tcliservice.SCALE]
			if scaleT != nil {
				scale = int64(scaleT.GetI32Value())
			} else {
				scale = 0
			}
			return precision, scale, true
		default:
		}
	}
	return 0, 0, false
}

var _ driver.RowsColumnTypePrecisionScale = (*hiveRows)(nil)
