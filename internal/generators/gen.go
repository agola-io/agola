package main

import "flag"

var componentName string

func init() {
	flag.StringVar(&componentName, "component", "", "component name")
}

func main() {
	flag.Parse()

	genInsertDelete()
	genFetch()
}
