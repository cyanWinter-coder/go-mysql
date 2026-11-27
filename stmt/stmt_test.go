package stmt

import (
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/stretchr/testify/require"
)

// Release drops the cached parsed fields; they are parsed again on demand.
func TestPreparedStmtRelease(t *testing.T) {
	raw := (&mysql.Field{Name: []byte("?"), Type: mysql.MYSQL_TYPE_LONG}).Dump()
	s := &PreparedStmt{RawParamFields: [][]byte{raw}}

	fields, err := s.GetParamFields()
	require.NoError(t, err)
	require.Len(t, fields, 1)
	require.NotNil(t, s.paramFields)

	s.Release()
	require.Nil(t, s.paramFields)
	require.Nil(t, s.columnFields)

	fields, err = s.GetParamFields()
	require.NoError(t, err)
	require.Len(t, fields, 1)
}
