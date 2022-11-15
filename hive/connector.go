package hive2

import (
	"context"
	"database/sql/driver"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/apache/thrift/lib/go/thrift"
	krb "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"github.com/mumuhhh/gohive2/hive/rpc/tcliservice"
	saslgsskerb "github.com/mumuhhh/gohive2/sasl/gsskerb"
	saslplain "github.com/mumuhhh/gohive2/sasl/plain"
)

type connector struct {
	params *ConnParams
}

const Kerberos = 1

func (c *connector) Driver() driver.Driver {
	return &HiveDriver{}
}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	fetchSize := int64(1000)
	if fetchSizeStr, ok := c.params.SessionVar["fetchSize"]; ok {
		i, err := strconv.ParseInt(fetchSizeStr, 10, 64)
		if err == nil {
			fetchSize = i
		}
	}
	transport, err := c.openTransport(ctx)
	if err != nil {
		return nil, err
	}

	protocol := thrift.NewTBinaryProtocolFactoryConf(&thrift.TConfiguration{})
	client := tcliservice.NewTCLIServiceClientFactory(transport, protocol)

	openResp, err := c.openSession(ctx, client)
	if err != nil {
		return nil, err
	}
	return &hiveConn{
		transport:  transport,
		client:     client,
		sessHandle: openResp.SessionHandle,
		protocol:   openResp.ServerProtocolVersion,
		fetchSize:  fetchSize,
		ctx:        ctx,
		params:     c.params,
	}, nil
}

func (c *connector) openTransport(ctx context.Context) (thrift.TTransport, error) {
	var transport thrift.TTransport
	hostPort := c.params.Addresses[0]
	transport, err := thrift.NewTSocketConf(hostPort, &thrift.TConfiguration{})
	if err != nil {
		return nil, err
	}

	if c.params.SessionVar["auth"] != "noSasl" {
		if principal, ok := c.params.SessionVar["principal"]; ok {
			if userPrincipal, ok := c.params.SessionVar["user.principal"]; ok {
				kt, err := keytab.Load(c.params.SessionVar["user.keytab"])
				if err != nil {
					return nil, err
				}
				krb5conf, err := config.Load(c.params.SessionVar["user.krb5.conf"])
				if err != nil {
					return nil, err
				}
				username := strings.Split(userPrincipal, "@")
				krbClient := krb.NewWithKeytab(username[0], username[1], kt, krb5conf)
				spn := strings.FieldsFunc(principal, func(r rune) bool {
					return r == '/' || r == '@'
				})
				host, _, err := net.SplitHostPort(hostPort)
				if err != nil {
					return nil, err
				} else {
					if addrs, err := net.LookupAddr(host); err != nil {
						return nil, err
					} else if len(addrs) > 0 {
						host = addrs[0]
					}
				}
				saslClient := saslgsskerb.NewGssKerbClient("", spn[0], host, krbClient)
				transport = NewTSaslClientTransport(transport, saslClient)
			}
		} else {
			username, ok := c.params.SessionVar["username"]
			if !ok {
				username = "anonymous"
			}
			password, ok := c.params.SessionVar["password"]
			if !ok {
				password = "anonymous"
			}
			saslClient := saslplain.NewPlainClient("", username, password)
			transport = NewTSaslClientTransport(transport, saslClient)
		}
	}

	if err := transport.Open(); err != nil {
		return nil, err
	}
	return transport, nil
}

func (c *connector) openSession(ctx context.Context, client *tcliservice.TCLIServiceClient) (*tcliservice.TOpenSessionResp, error) {
	openSessionReq := tcliservice.NewTOpenSessionReq()
	openSessionReq.ClientProtocol = tcliservice.TProtocolVersion_HIVE_CLI_SERVICE_PROTOCOL_V8
	openConf := map[string]string{}
	for k, v := range c.params.HiveConf {
		openConf["set:hiveconf:"+k] = v
	}
	// For remote JDBC client, try to set the hive var using 'set hivevar:key=value'
	for k, v := range c.params.HiveVar {
		openConf["set:hivevar:"+k] = v
	}
	// switch the database
	openConf["use:database"] = c.params.DBName

	// set the session configuration
	for k, v := range c.params.SessionVar {
		if k == "hive.server2.proxy.user" {
			openConf["hive.server2.proxy.user"] = v
			break
		}
	}
	openSessionReq.Configuration = openConf
	// Store the user name in the open request in case no non-sasl authentication
	if c.params.SessionVar["auth"] == "noSasl" {
		username := c.params.SessionVar["username"]
		if username != "" {
			openSessionReq.Username = &username
		}
		password := c.params.SessionVar["password"]
		if password != "" {
			openSessionReq.Password = &password
		}
	}
	openResp, err := client.OpenSession(ctx, openSessionReq)
	if err != nil {
		return nil, err
	}

	if !verifySuccess(openResp.Status, false) {
		return nil, fmt.Errorf("Error from server: %s", openResp.Status.String())
	}
	return openResp, nil
}
