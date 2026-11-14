package port

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

type Allocator struct {
	reserved sets.Set[int]
	used     sets.Set[int]
	mu       sync.Mutex
}

// NewAllocator return a port allocator for testing.
// Example: from: 10, to: 20, mod 4, index 1
// Reserved ports: 13, 17
func NewAllocator(from int, to int, mod int, index int) *Allocator {
	pa := &Allocator{
		reserved: sets.New[int](),
		used:     sets.New[int](),
	}

	if mod <= 0 {
		mod = 1
	}
	if index < 0 {
		index = 0
	} else {
		index %= mod
	}

	for i := from; i <= to; i++ {
		if i%mod == index {
			pa.reserved.Insert(i)
		}
	}
	return pa
}

func (pa *Allocator) Get() int {
	return pa.GetByName("")
}

func (pa *Allocator) GetByName(portName string) int {
	var builder *nameBuilder
	if portName == "" {
		builder = &nameBuilder{}
	} else {
		var err error
		builder, err = unmarshalFromName(portName)
		if err != nil {
			fmt.Println(err, portName)
			return 0
		}
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	for range 20 {
		port := pa.getByRange(builder.rangePortFrom, builder.rangePortTo)
		if port == 0 {
			return 0
		}

		l, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		if err != nil {
			// Maybe not controlled by us, mark it used.
			pa.used.Insert(port)
			continue
		}
		_ = l.Close()

		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		if err != nil {
			pa.used.Insert(port)
			continue
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			// Maybe not controlled by us, mark it used.
			pa.used.Insert(port)
			continue
		}
		_ = udpConn.Close()

		pa.used.Insert(port)
		return port
	}
	return 0
}

func (pa *Allocator) getByRange(from, to int) int {
	if from <= 0 {
		port, ok := pa.reserved.PopAny()
		if !ok {
			return 0
		}
		return port
	}

	// choose a port between from - to
	var matching []int
	ports := pa.reserved.UnsortedList()
	for _, port := range ports {
		if port >= from && port <= to {
			matching = append(matching, port)
		}
	}
	if len(matching) == 0 {
		return 0
	}

	// Pick randomly from matching ports to mitigate TOCTOU collision under concurrency
	selected := matching[rand.IntN(len(matching))]
	pa.reserved.Delete(selected)
	return selected
}

func (pa *Allocator) Release(port int) {
	if port <= 0 {
		return
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	if pa.used.Has(port) {
		pa.used.Delete(port)
		pa.reserved.Insert(port)
	}
}
