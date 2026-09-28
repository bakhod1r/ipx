package ipx

import "errors"

// Sentinel errors. Match with errors.Is.
var (
	ErrInvalidAddr     = errors.New("ipx: invalid IP address")
	ErrInvalidPrefix   = errors.New("ipx: invalid CIDR prefix")
	ErrInvalidRange    = errors.New("ipx: invalid IP range")
	ErrInvalidPort     = errors.New("ipx: invalid port")
	ErrInvalidEndpoint = errors.New("ipx: invalid endpoint")
	ErrInvalidReverse  = errors.New("ipx: invalid reverse DNS name")
	ErrHostBitsSet     = errors.New("ipx: prefix has host bits set")
	ErrFamilyMismatch  = errors.New("ipx: IPv4/IPv6 family mismatch")
	ErrOverflow        = errors.New("ipx: address arithmetic overflow")
	ErrExhausted       = errors.New("ipx: address pool exhausted")
	ErrNotInPool       = errors.New("ipx: address outside pool")
	ErrInUse           = errors.New("ipx: address already allocated or reserved")
)
