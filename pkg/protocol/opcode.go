package protocol

import "fmt"

// OpCode in the MongoDB protocol
type OpCode int32

const (
	// OpInvalid is a missing / invalid opcode
	OpInvalid = OpCode(0)
	// OpReply is a reply to a client request. Header.ResponseTo is set
	OpReply = OpCode(1)
	// OpUpdate updates a document (unacknowledged)
	OpUpdate = OpCode(2001)
	// OpInsert inserts a new document (unacknowledged)
	OpInsert = OpCode(2002)
	// OpQuery queries a collection
	OpQuery = OpCode(2004)
	// OpGetMore gets more data from a query using a cursor
	OpGetMore = OpCode(2005)
	// OpDelete deletes documents (unacknowledged)
	OpDelete = OpCode(2006)
	// OpKillCursors notifies the database the client has finished with the cursor
	OpKillCursors = OpCode(2007)
	// OpCompressed is a compressed op
	OpCompressed = OpCode(2012)
	// OpMsg sends a message using the format introduced in MongoDB 3.6
	OpMsg = OpCode(2013)
)

// IsValidOpCode checks if an opcode is valid
func IsValidOpCode(o OpCode) bool {
	switch o {
	case 1, 2001, 2002, 2004, 2005, 2006, 2007, 2012, 2013:
		return true
	}
	return false
}

// String representation
func (o OpCode) String() string {
	switch o {
	case OpReply:
		return "OP_REPLY"
	case OpUpdate:
		return "OP_UPDATE"
	case OpInsert:
		return "OP_INSERT"
	case OpQuery:
		return "OP_QUERY"
	case OpGetMore:
		return "OP_GET_MORE"
	case OpDelete:
		return "OP_DELETE"
	case OpKillCursors:
		return "OP_KILL_CURSORS"
	case OpCompressed:
		return "OP_COMPRESSED"
	case OpMsg:
		return "OP_MSG"
	}
	return fmt.Sprintf("Unknown: %d", o)
}
