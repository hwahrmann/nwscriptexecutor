/*
   NetWitness Script Executor Options
   Copyright (C) 2024  Helmut Wahrmann

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
)

var (
	version string
	conf    *config.Config
)

type Options struct {
	Version string
	Config  *config.Config
}

func init() {
	if version == "" {
		version = "1.0"
	}

	conf = config.New("conf")
	conf.WithOptions(config.ParseEnv)
	conf.AddDriver(yaml.Driver)
	err := conf.LoadFiles("config.yml")
	if err != nil {
		panic(err)
	}
}

func GetOptions() *Options {
	return &Options{
		Version: version,
		Config:  conf,
	}
}
