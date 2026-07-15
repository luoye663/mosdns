/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	_ "github.com/IrineSistiana/mosdns/v5/plugin"
	_ "github.com/IrineSistiana/mosdns/v5/tools"
	"github.com/spf13/cobra"
	_ "net/http/pprof"
)

var (
	projectVersion = "dev"
	gitCommit      = "unknown"
	mosdnsBase     = "v5.3.4"
	buildTime      = "unknown"
)

func init() {
	coremain.AddSubCmd(&cobra.Command{
		Use:   "version",
		Short: "Print out version info and exit.",
		Run: func(cmd *cobra.Command, args []string) {
			// 构建信息用于运行期核对，不能包含规则、token 或上游地址。
			fmt.Printf("version=%s commit=%s mosdns_base=%s build_time=%s\n", projectVersion, gitCommit, mosdnsBase, buildTime)
		},
	})
}

func main() {
	if err := coremain.Run(); err != nil {
		mlog.S().Fatal(err)
	}
}
