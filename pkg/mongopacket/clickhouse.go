package mongopacket

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Store packet and Mongo messages into Clickhouse

const createPacketSQL = `
CREATE TABLE IF NOT EXISTS mp_packets (
	group String,
	packet_id UInt64,
	time DateTime,
	time_us UInt64,
	seq UInt32,
	ack UInt32,
	src String,
	src_port String,
	dst String,
	dst_port String,
	flag_syn UInt8,
	flag_fin UInt8,
	flag_rst UInt8,
	flag_psh UInt8,
	flag_ack UInt8,
	size UInt32
) ENGINE = MergeTree()
PRIMARY KEY (packet_id)
ORDER BY (packet_id)
`

const insertPacketSQL = `
INSERT INTO mp_packets (
	group, packet_id, time, time_us,
	seq, ack,
	src, src_port, dst, dst_port,
	flag_syn,	flag_fin,	flag_rst,	flag_psh,	flag_ack,
	size
)
VALUES (
	?, ?, ?, ?,
	?, ?,
	?, ?, ?, ?,
	?, ?, ?, ?, ?,
	?
)
`

const createEventSQL = `
CREATE TABLE IF NOT EXISTS mp_events (
	group String,
	event_id UInt64,
	start_time DateTime,
	start_time_us UInt64,
	end_time DateTime,
	end_time_us UInt64,
	stream_id UInt64,
	stream_start UInt8,
	stream_end UInt8,
	request_id UInt32,
	response_to UInt32,
	src String,
	src_port String,
	dst String,
	dst_port String,
	opcode String,
	op String,
	packets String
) ENGINE = MergeTree()
PRIMARY KEY (event_id)
ORDER BY (event_id)
`

const insertEventSQL = `
INSERT INTO mp_events (
	group, event_id,
	start_time, start_time_us,
	end_time, end_time_us,
	stream_id, stream_start, stream_end,
	request_id, response_to,
	src, src_port, dst, dst_port,
	opcode, op, packets
) VALUES (
	?, ?,
	?, ?,
	?, ?,
	?, ?, ?,
	?, ?,
	?, ?, ?, ?,
	?, ?, ?
)
`

// Clickhouse database connection state
type Clickhouse struct {
	db *sql.DB
}

// NewClickhouse ..
func NewClickhouse(url string) (*Clickhouse, error) {
	db, err := sql.Open("clickhouse", url)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Creating the tables if they don't exist
	if err = execute(ctx, db, createPacketSQL, nil); err != nil {
		fmt.Println("FAIL", err)
		return nil, err
	}
	if err = execute(ctx, db, createEventSQL, nil); err != nil {
		return nil, err
	}

	return &Clickhouse{db: db}, nil
}

// SaveMongoEvents ..
func (c *Clickhouse) SaveMongoEvents(events []*MongoEvent) error {
	var rows [][]interface{}
	for _, e := range events {
		start := e.Start.UnixNano() / 1e3
		end := e.End.UnixNano() / 1e3

		op, err := json.Marshal(e.Op)
		if err != nil {
			fmt.Println("error json-encoding mongo operation", err)
			continue
		}
		pkts, err := json.Marshal(e.Packets)
		if err != nil {
			fmt.Println("error json-encoding mongo event packets", err)
			continue
		}

		rows = append(rows, []interface{}{
			e.Group,
			e.EventID,
			start / 1e6,
			start,
			end / 1e6,
			end,
			e.StreamID, e.StreamStart, e.StreamEnd,
			e.Op.GetHeader().RequestID, e.Op.GetHeader().ResponseTo,
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort,
			e.Op.GetHeader().OpCode.String(),
			string(op),
			string(pkts),
		})

	}
	return execute(context.Background(), c.db, insertEventSQL, rows)
}

// SavePacketEvents ..
func (c *Clickhouse) SavePacketEvents(packets []*PacketEvent) error {
	var rows [][]interface{}
	for _, p := range packets {
		t := p.Time.UnixNano() / 1e3
		rows = append(rows, []interface{}{
			p.Group,
			p.PacketID,
			t / 1e6,
			t,
			p.Seq,
			p.Ack,
			p.SrcIP,
			p.SrcPort,
			p.DstIP,
			p.DstPort,
			p.FlagSYN,
			p.FlagFIN,
			p.FlagRST,
			p.FlagPSH,
			p.FlagACK,
			p.SizeTCP,
		})
	}
	return execute(context.Background(), c.db, insertPacketSQL, rows)
}

// Close ..
func (c *Clickhouse) Close() error {
	return c.db.Close()
}

func execute(ctx context.Context, db *sql.DB, statementSQL string, args [][]interface{}) error {
	var tx *sql.Tx
	var stmt *sql.Stmt
	var err error

	// Start a transaction
	tx, err = db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  false,
	})
	if err != nil {
		return err
	}

	// Prepare the SQL statement
	stmt, err = tx.PrepareContext(ctx, statementSQL)
	if err != nil {
		goto fail
	}
	defer stmt.Close()

	if args == nil {
		// Execute a statement with no arguments
		if _, err = stmt.ExecContext(ctx); err != nil {
			goto fail
		}
	} else {
		// Execute the statement with arguments
		for _, arg := range args {
			if _, err = stmt.ExecContext(ctx, arg...); err != nil {
				goto fail
			}
		}
	}

	// Commit
	return tx.Commit()

fail:
	// Rollback the txn
	tx.Rollback()
	return err
}
