package main

import (
	"encoding/binary"
	"sort"
)

func parseIPv4OwnerPIDListeners(buffer []byte, ids map[uint32]struct{}) []uint16 {
	if len(buffer) < 4 || len(ids) == 0 {
		return nil
	}
	const rowSize = 24
	count := int(binary.LittleEndian.Uint32(buffer[:4]))
	ports := map[uint16]struct{}{}
	for i := 0; i < count; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buffer) {
			break
		}
		row := buffer[off : off+rowSize]
		if _, ok := ids[binary.LittleEndian.Uint32(row[20:24])]; !ok {
			continue
		}
		address := binary.LittleEndian.Uint32(row[4:8])
		if address != 0 && address != 0x0100007f {
			continue
		}
		raw := binary.LittleEndian.Uint32(row[8:12])
		port := uint16((raw&0xff)<<8 | (raw&0xff00)>>8)
		if port != 0 {
			ports[port] = struct{}{}
		}
	}
	result := make([]uint16, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
