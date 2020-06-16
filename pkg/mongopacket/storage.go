package mongopacket

// Storage ..
type Storage interface {
	SaveMongoEvents(e []*MongoEvent) error
	SavePacketEvents(e []*PacketEvent) error
	Flush() error
}
