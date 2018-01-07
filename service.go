package main

type Process struct {
	PID  int
	Name string
}

type Service struct {
	Name     string
	Device   string
	Protocol string
	IP       string
	Port     int
}
