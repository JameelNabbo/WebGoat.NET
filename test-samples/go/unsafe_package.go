package main

import (
	"fmt"
	"unsafe"
)

// VULN: Using unsafe.Pointer for type manipulation
func unsafeConvert(i int) float64 {
	return *(*float64)(unsafe.Pointer(&i))
}

// VULN: Using unsafe.Sizeof
func getSize() {
	var x struct {
		a bool
		b int64
		c bool
	}
	fmt.Printf("Size: %d, Alignment: %d\n", unsafe.Sizeof(x), unsafe.Alignof(x))
}

// VULN: Arbitrary memory read via unsafe
func readMemory(ptr uintptr) byte {
	return *(*byte)(unsafe.Pointer(ptr))
}

// VULN: Type punning with unsafe
func intToBytes(val int64) []byte {
	size := int(unsafe.Sizeof(val))
	result := make([]byte, size)
	for i := 0; i < size; i++ {
		result[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&val)) + uintptr(i)))
	}
	return result
}
