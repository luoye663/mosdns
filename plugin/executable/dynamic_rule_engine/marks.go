package dynamic_rule_engine

import "fmt"

// Marks 集中管理动态规则使用的 request mark，避免业务代码散落魔法数字。
type Marks struct {
	AccessBlock uint32 `yaml:"access_block"`
	AccessAllow uint32 `yaml:"access_allow"`
	RouteLocal  uint32 `yaml:"route_local"`
	RouteRemote uint32 `yaml:"route_remote"`
	NoLog       uint32 `yaml:"no_log"`
}

func defaultMarks() Marks {
	return Marks{AccessBlock: 1001, AccessAllow: 1002, RouteLocal: 1101, RouteRemote: 1102, NoLog: 1201}
}

func (m Marks) validate() error {
	values := []struct {
		name  string
		value uint32
	}{
		{"access_block", m.AccessBlock}, {"access_allow", m.AccessAllow}, {"route_local", m.RouteLocal},
		{"route_remote", m.RouteRemote}, {"no_log", m.NoLog},
	}
	seen := make(map[uint32]string, len(values))
	for _, item := range values {
		if item.value == 0 {
			return fmt.Errorf("marks.%s must be greater than zero", item.name)
		}
		if previous, ok := seen[item.value]; ok {
			return fmt.Errorf("marks.%s duplicates marks.%s", item.name, previous)
		}
		seen[item.value] = item.name
	}
	return nil
}
