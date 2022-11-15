package hive2_test

import (
	"database/sql"
	"encoding/json"
	"testing"

	_ "github.com/mumuhhh/gohive2/hive"
	hivething "github.com/mumuhhh/gohive2/hive"
)

func TestConnect(t *testing.T) {
	driver, err := sql.Open("hive2",
		"hive2://172.16.166.66:10000/default;principal=hive/_HOST@HADOOP.COM;"+
			"user.principal=hdfs@HADOOP.COM;"+
			"user.keytab=D:/kerberos/hdfs.keytab;"+
			"user.krb5.conf=D:/kerberos/krb5.conf")
	if err != nil {
		t.Fatal(err)
		return
	}
	rows, err := driver.Query("show tables")
	if err != nil {
		t.Fatal(err)
		return
	}

	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(columns)

	val := ""
	for rows.Next() {
		rows.Scan(&val)
		t.Log(val)
	}
}

func TestConnParams(t *testing.T) {
	params, err := hivething.ParseUrl("hive2://server:10001/default;principal=hive/_HOST@HADOOP.COM;" +
		"user.principal=hdfs@HADOOP.COM;" +
		"user.keytab=D:/kerberos/hdfs.keytab;" +
		"user.krb5.conf=D:/kerberos/krb5.conf" +
		"?hive.server2.thrift.http.path=hs2" +
		"#gfd=gdfg")
	if err != nil {
		t.Fatal(err)
		return
	}
	marshal, _ := json.Marshal(params)
	t.Log(string(marshal))
}
