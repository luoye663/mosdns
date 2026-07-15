package dynamic_rule_engine

import "sync/atomic"

// Store 只以原子指针发布已完整编译的快照，DNS 请求无需等待写锁。
type Store struct {
	current atomic.Pointer[CompiledSnapshot]
}

func (s *Store) Load() *CompiledSnapshot { return s.current.Load() }

func (s *Store) Swap(snapshot *CompiledSnapshot) *CompiledSnapshot {
	if snapshot == nil {
		panic("dynamic_rule_engine: cannot publish a nil snapshot")
	}
	return s.current.Swap(snapshot)
}
